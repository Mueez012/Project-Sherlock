"""Full-report TTP extraction (Phase 8B): how the paper uses the model on CTI reports.

  report text -> sentences (preprocessing/sentences.py) -> SecureBERT tokens
  -> TTP model -> per-sentence label probabilities -> report-level TTP set

A label enters the report's TTP set when it passes its threshold in at least
`min_sentences` sentences, or when its highest sentence probability reaches
`max_prob` (if given). Each TTP lists the sentences that triggered it (evidence).

The top-1 rule from the decision layer is NOT used here: in the training data
every sentence has a TTP, but most sentences of a real report describe none,
so forcing one label per sentence would flood the report with false positives.

Single report:
  python -m ttp_extraction.inference.extract_report --run concat_seed_0 --text-file report.txt
Batch over the authors' report file, then compare with their TTP lists:
  python -m ttp_extraction.inference.extract_report --run concat_seed_0 --batch authors
"""
from __future__ import annotations

import argparse
import json
import re
from itertools import product
from pathlib import Path

import numpy as np
import torch

LABEL_VOCAB = Path("artifacts/label_vocab.json")
AUTHORS_TTP = Path("ThreatMAMBA-main/CTI2Attacker_TTP.csv")
CLEANED = Path("ThreatMAMBA-main/cleaned_CTI2Attacker.csv")
EMBEDDING_ROOT = Path.home() / "ttp_cache" / "report_embeddings"


class ReportExtractor:
    def __init__(self, model, tokenizer, encoder, labels, thresholds, n_tactics: int,
                 hierarchy_map: dict | None = None, batch_size: int = 32, device=None):
        self.model, self.tokenizer, self.encoder = model.eval(), tokenizer, encoder
        self.labels, self.n_tactics = list(labels), n_tactics
        self.thresholds = np.asarray(thresholds, dtype=float)
        self.hierarchy_map = {int(k): v for k, v in (hierarchy_map or {}).items()}
        self.batch_size = batch_size
        self.device = device or next(model.parameters()).device

    @torch.no_grad()
    def embed(self, sentences: list[str]) -> list[np.ndarray]:
        """SecureBERT token embeddings per sentence (real tokens only), float16."""
        from ttp_extraction.preprocessing.tokenization import encode

        out = []
        for start in range(0, len(sentences), self.batch_size):
            batch = encode(self.tokenizer, sentences[start : start + self.batch_size])
            ids = torch.from_numpy(batch["input_ids"]).to(self.device)
            mask = torch.from_numpy(batch["attention_mask"]).to(self.device)
            hidden = self.encoder(input_ids=ids, attention_mask=mask).last_hidden_state
            for row, n in enumerate(mask.sum(1).tolist()):
                out.append(hidden[row, :n].half().cpu().numpy())
        return out

    @torch.no_grad()
    def probabilities(self, embeddings: list[np.ndarray]) -> np.ndarray:
        """(n_sentences, L) label probabilities."""
        from ttp_extraction.data.batching import pad_batch

        if not embeddings:
            return np.zeros((0, len(self.labels)))
        # Similar lengths together: less padding, same results (rows are independent).
        order = np.argsort([len(e) for e in embeddings], kind="stable")
        probs = np.zeros((len(embeddings), len(self.labels)))
        for start in range(0, len(order), self.batch_size):
            idx = order[start : start + self.batch_size]
            x, mask = pad_batch([embeddings[i].astype(np.float32) for i in idx])
            out = self.model(x.to(self.device), mask.to(self.device))
            probs[idx] = out["probabilities"].float().cpu().numpy()
        return probs

    def sentence_labels(self, probs: np.ndarray) -> np.ndarray:
        pred = probs > self.thresholds[None, :]
        for technique, tactics in self.hierarchy_map.items():
            for tactic in tactics:
                pred[:, tactic] |= pred[:, technique]
        return pred

    def aggregate(self, sentences: list[str], probs: np.ndarray, min_sentences: int = 1,
                  max_prob: float | None = None, max_evidence: int = 5) -> dict:
        pred = self.sentence_labels(probs)
        ttps = []
        for j, label in enumerate(self.labels):
            hits = np.flatnonzero(pred[:, j])
            best = float(probs[:, j].max()) if len(probs) else 0.0
            if len(hits) >= min_sentences or (max_prob is not None and best >= max_prob):
                ranked = hits[np.argsort(-probs[hits, j])][:max_evidence]
                ttps.append({
                    "id": label, "kind": "tactic" if j < self.n_tactics else "technique",
                    "max_probability": round(best, 4), "n_sentences": int(len(hits)),
                    "evidence": [{"sentence": int(i), "probability": round(float(probs[i, j]), 4),
                                  "text": sentences[i]} for i in ranked],
                })
        ttps.sort(key=lambda t: (t["kind"] != "tactic", -t["max_probability"]))
        return {"n_sentences": len(sentences), "ttps": ttps}

    def extract(self, text: str, **aggregate_args) -> dict:
        from ttp_extraction.preprocessing.sentences import split_sentences

        sentences = split_sentences(text)
        probs = self.probabilities(self.embed(sentences))
        return self.aggregate(sentences, probs, **aggregate_args)


def load_extractor(run_dir: Path, decision: Path | None = None, device=None) -> ReportExtractor:
    from ttp_extraction.data.labels import LabelVocab
    from ttp_extraction.preprocessing.tokenization import load_tokenizer
    from ttp_extraction.securebert.encoder import load_encoder
    from ttp_extraction.training.train import TrainConfig, build_model

    device = device or torch.device("cuda" if torch.cuda.is_available() else "cpu")
    vocab = LabelVocab.load(LABEL_VOCAB)
    raw = json.loads((run_dir / "config.json").read_text(encoding="utf-8"))
    if "encoder_lr" in raw:   # fine-tuned SecureBERT: use its own encoder and head
        from transformers import AutoConfig, AutoModel

        from ttp_extraction.classifier.model import TTPExtractorE2E
        from ttp_extraction.preprocessing.tokenization import MODEL_NAME
        from ttp_extraction.training.train_finetune import FinetuneConfig

        fc = FinetuneConfig(**raw)
        e2e = TTPExtractorE2E(AutoModel.from_config(AutoConfig.from_pretrained(MODEL_NAME)),
                              n_labels=len(vocab), d_model=fc.d_model, d_state=fc.d_state,
                              n_layers=fc.n_layers, kernel_size=fc.kernel_size,
                              dropout=fc.dropout, classifier=fc.classifier).to(device)
        e2e.load_state_dict(torch.load(run_dir / "best.pt", map_location=device, weights_only=True))
        model, encoder = e2e.head, e2e.encoder.eval()
    else:
        config = TrainConfig.from_dict(raw)
        model = build_model(config, len(vocab)).to(device)
        model.load_state_dict(torch.load(run_dir / "best.pt", map_location=device))
        encoder = load_encoder(device=device)
    thresholds, hierarchy = np.full(len(vocab), 0.5), None
    if decision is not None:
        layer = json.loads(decision.read_text(encoding="utf-8"))
        thresholds = np.asarray(layer["thresholds"])
        hierarchy = layer["hierarchy_map"] if layer.get("hierarchy") else None
    extractor = ReportExtractor(model, load_tokenizer(), encoder, vocab.labels,
                                thresholds, len(vocab.tactics), hierarchy, device=device)
    # Embeddings from a fine-tuned encoder are specific to that run.
    extractor.embedding_key = run_dir.name if "encoder_lr" in raw else "securebert"
    return extractor


# ---------------------------------------------------------------- batch mode

def normalise(text: str, n: int = 300) -> str:
    return re.sub(r"[^a-z0-9]", "", str(text).lower())[:n]


def load_reports(source: str) -> list[dict]:
    """[{id, group, text}] for the authors' TTP file (deduplicated) or the cleaned corpus."""
    import pandas as pd

    if source == "authors":
        df = pd.read_csv(AUTHORS_TTP).drop_duplicates("original_index")   # every row appears twice
        return [{"id": int(r.original_index), "group": r.Group, "text": r.Context}
                for r in df.itertuples()]
    df = pd.read_csv(CLEANED)
    return [{"id": int(r.index), "group": r.group_name, "text": r.cti_content}
            for r in df.itertuples()]


def run_batch(extractor: ReportExtractor, source: str, out_path: Path, embedding_root: Path,
              limit: int | None = None, **aggregate_args) -> None:
    """Resumable: reports already in out_path are skipped; embeddings cached per report."""
    from ttp_extraction.preprocessing.sentences import split_sentences

    done = set()
    if out_path.exists():
        done = {json.loads(line)["id"] for line in out_path.read_text(encoding="utf-8").splitlines() if line}
    reports = [r for r in load_reports(source) if r["id"] not in done][:limit]
    cache_dir = embedding_root / getattr(extractor, "embedding_key", "securebert") / source
    cache_dir.mkdir(parents=True, exist_ok=True)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    print(f"{len(done)} reports done, {len(reports)} to go", flush=True)
    for k, report in enumerate(reports, 1):
        sentences = split_sentences(report["text"])
        cached = cache_dir / f"{report['id']}.npz"
        if cached.exists():
            stored = np.load(cached)
            flat, offsets = stored["flat"], stored["offsets"]
            embeddings = [flat[offsets[i] : offsets[i + 1]] for i in range(len(offsets) - 1)]
        else:
            embeddings = extractor.embed(sentences)
            lengths = [len(e) for e in embeddings]
            np.savez(cached, flat=np.concatenate(embeddings) if embeddings else np.zeros((0, 768), np.float16),
                     offsets=np.concatenate([[0], np.cumsum(lengths)]).astype(np.int64))
        result = extractor.aggregate(sentences, extractor.probabilities(embeddings), **aggregate_args)
        record = {"id": report["id"], "group": report["group"], **result}
        with out_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")
        if k % 25 == 0:
            print(f"  {k}/{len(reports)}", flush=True)


def sweep_agreement(extractor: ReportExtractor, source_root: Path, out_dir: Path,
                    thresholds=(0.5, 0.3, 0.2, 0.1, 0.05), min_sentences=(1, 2)) -> list[dict]:
    """Agreement with the authors for several report-level rules, from cached embeddings.

    Only the small TTP head is re-run, so this takes minutes, not hours.
    """
    reports = {r["id"]: r for r in load_reports("authors")}
    probs = {}
    for path in sorted(source_root.glob("*.npz")):
        stored = np.load(path)
        flat, offsets = stored["flat"], stored["offsets"]
        embeddings = [flat[offsets[i] : offsets[i + 1]] for i in range(len(offsets) - 1)]
        probs[int(path.stem)] = extractor.probabilities(embeddings)
    rows, base = [], extractor.thresholds.copy()
    for tau, k in product(thresholds, min_sentences):
        extractor.thresholds = np.where(np.arange(len(base)) < extractor.n_tactics, base, tau)
        out = out_dir / f"sweep_t{tau}_k{k}.jsonl"
        with out.open("w", encoding="utf-8") as handle:
            for rid, p in probs.items():
                result = extractor.aggregate([""] * len(p), p, min_sentences=k, max_evidence=0)
                handle.write(json.dumps({"id": rid, "group": reports[rid]["group"], **result}) + "\n")
        scores = compare_with_authors(out, extractor.labels[extractor.n_tactics :])
        rows.append({"technique_threshold": tau, "min_sentences": k, "f1": scores["micro"]["f1"],
                     "precision": scores["micro"]["precision"], "recall": scores["micro"]["recall"],
                     "jaccard": scores["mean_jaccard"],
                     "ours_per_report": scores["mean_techniques_per_report"]["ours"]})
        out.unlink()
    extractor.thresholds = base
    return rows


def flatten(items):
    for item in items:
        if isinstance(item, list):
            yield from flatten(item)
        else:
            yield item


def compare_with_authors(ours_path: Path, technique_ids) -> dict:
    """Report-level agreement with CTI2Attacker_TTP.csv over the shared technique labels.

    This is AGREEMENT with the authors' extractor output, not accuracy against
    ground truth. Their lists use sub-techniques (rolled up to the parent here)
    and some techniques outside our 189 labels (counted, then left out).
    """
    import pandas as pd

    ours = {}
    for line in ours_path.read_text(encoding="utf-8").splitlines():
        record = json.loads(line)
        ours[record["id"]] = {t["id"] for t in record["ttps"] if t["kind"] == "technique"}
    theirs_df = pd.read_csv(AUTHORS_TTP).drop_duplicates("original_index")
    space = set(technique_ids)
    tp = fp = fn = 0
    per_report, outside = [], 0
    for r in theirs_df.itertuples():
        if int(r.original_index) not in ours:
            continue
        raw = {str(t).split(".")[0] for t in flatten(json.loads(r.TTPs))}
        theirs = raw & space
        outside += len(raw - space)
        mine = ours[int(r.original_index)]
        a, b, c = len(mine & theirs), len(mine - theirs), len(theirs - mine)
        tp, fp, fn = tp + a, fp + b, fn + c
        p = a / (a + b) if a + b else 0.0
        rec = a / (a + c) if a + c else 0.0
        per_report.append({"p": p, "r": rec, "f1": 2 * p * rec / (p + rec) if p + rec else 0.0,
                           "jaccard": a / (a + b + c) if a + b + c else 1.0,
                           "ours": len(mine), "theirs": len(theirs)})
    P, R = tp / max(tp + fp, 1), tp / max(tp + fn, 1)
    mean = lambda k: float(np.mean([x[k] for x in per_report])) if per_report else 0.0
    return {
        "reports_compared": len(per_report),
        "micro": {"precision": 100 * P, "recall": 100 * R,
                  "f1": 100 * 2 * P * R / (P + R) if P + R else 0.0},
        "macro_over_reports": {"precision": 100 * mean("p"), "recall": 100 * mean("r"),
                               "f1": 100 * mean("f1")},
        "mean_jaccard": mean("jaccard"),
        "mean_techniques_per_report": {"ours": mean("ours"), "theirs": mean("theirs")},
        "their_labels_outside_our_189": outside,
        "note": "agreement with the authors' published TTP lists, not ground-truth accuracy",
    }


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--run", required=True, help="run name under runs/")
    p.add_argument("--runs", type=Path, default=Path("runs"))
    p.add_argument("--decision", type=Path, default=None,
                   help="decision_*.json from evaluate.py (thresholds, hierarchy); default 0.5")
    p.add_argument("--text-file", type=Path, default=None)
    p.add_argument("--batch", choices=("authors", "cleaned"), default=None)
    p.add_argument("--limit", type=int, default=None)
    p.add_argument("--min-sentences", type=int, default=1)
    p.add_argument("--max-prob", type=float, default=None)
    p.add_argument("--embedding-cache", type=Path, default=EMBEDDING_ROOT)
    p.add_argument("--out", type=Path, default=None)
    p.add_argument("--sweep", action="store_true",
                   help="agreement with the authors for several thresholds (needs a finished --batch authors)")
    args = p.parse_args()

    extractor = load_extractor(args.runs / args.run, args.decision)
    aggregate_args = {"min_sentences": args.min_sentences, "max_prob": args.max_prob}
    if args.sweep:
        root = args.embedding_cache / getattr(extractor, "embedding_key", "securebert") / "authors"
        rows = sweep_agreement(extractor, root, Path("reports/report_extraction"))
        out = Path("reports/report_extraction") / f"{args.run}_authors_sweep.json"
        out.write_text(json.dumps(rows, indent=2), encoding="utf-8")
        print(f"{'tech thr':>8}{'min sent':>9}{'P':>7}{'R':>7}{'F1':>7}{'Jacc':>7}{'#ours':>7}")
        for r in rows:
            print(f"{r['technique_threshold']:8}{r['min_sentences']:9}{r['precision']:7.1f}{r['recall']:7.1f}"
                  f"{r['f1']:7.1f}{r['jaccard']:7.3f}{r['ours_per_report']:7.1f}")
        return
    if args.text_file:
        result = extractor.extract(args.text_file.read_text(encoding="utf-8"), **aggregate_args)
        text = json.dumps(result, indent=2, ensure_ascii=False)
        if args.out:
            args.out.write_text(text, encoding="utf-8")
        print(text)
        return
    if args.batch:
        tag = f"min{args.min_sentences}" + (f"_p{args.max_prob}" if args.max_prob else "")
        out = args.out or Path("reports/report_extraction") / f"{args.run}_{args.batch}_{tag}.jsonl"
        run_batch(extractor, args.batch, out, args.embedding_cache, args.limit, **aggregate_args)
        if args.batch == "authors":
            scores = compare_with_authors(out, extractor.labels[extractor.n_tactics :])
            out.with_suffix(".agreement.json").write_text(json.dumps(scores, indent=2), encoding="utf-8")
            print(json.dumps(scores, indent=2))
        return
    p.error("give --text-file or --batch")


if __name__ == "__main__":
    main()
