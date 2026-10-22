"""Evaluate the model on REAL, published CTI reports whose ATT&CK techniques are known.

Source: CISA joint cybersecurity advisories (public domain, US government). Each advisory tags
the behaviour it describes with ATT&CK ids, inline ("... downloaded additional tools [T1105]")
and in ATT&CK tables. Those ids are the ANSWER KEY.

  prepare   HTML -> (a) answer key: every T#### id on the page, rolled up to the parent technique;
                    (b) model input: the advisory prose with every <table> removed and every
                        T#### id deleted, so the model has to infer techniques from the text alone.
  leakage   how many advisory sentences also occur in the training sentences (CTI2TTPs.csv);
            MITRE's procedure examples quote CISA advisories, so older advisories can overlap.
  score     run a bundle (or the API) on the cleaned texts and score against the answer key.

  python -m ttp_extraction.evaluation.real_reports prepare --raw ../eval_data/cisa_raw --out ../eval_data/cisa
  python -m ttp_extraction.evaluation.real_reports score --data ../eval_data/cisa_full ../eval_data/cisa_prose       --bundle models/ttp-v1 models/ttp-v2 --out reports/real_reports_eval.json
"""
from __future__ import annotations

import argparse
import json
import re
import time
from pathlib import Path

import numpy as np

TECH_ID = re.compile(r"\bT1\d{3}(?:\.\d{3})?\b")
BRACKETED = re.compile(r"\[\s*T1\d{3}(?:\.\d{3})?\s*\]|\(\s*T1\d{3}(?:\.\d{3})?\s*\)")
PUBLISHED_AFTER_ATTACK_V14 = "aa24"   # ATT&CK v14 (the label set) was released Oct 2023
ATTACK_V14_RELEASE = "2023-10-31"


def normalise(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", s.lower()).strip()


# ------------------------------------------------------------------ prepare
def prepare_one(html_path: Path, keep_table_text: bool = True) -> dict:
    from bs4 import BeautifulSoup

    soup = BeautifulSoup(html_path.read_text(encoding="utf-8", errors="replace"), "html.parser")
    title = (soup.title.get_text() if soup.title else html_path.stem).replace(" | CISA", "").strip()
    main = soup.find("main") or soup
    for tag in main(["script", "style", "nav", "header", "footer", "aside", "form", "noscript"]):
        tag.decompose()
    # Related-content teasers at the bottom of CISA pages are other advisories: drop them.
    for teaser in main.select("article.c-teaser, .c-related, .l-related, .c-view"):
        teaser.decompose()
    truth_raw = sorted(set(TECH_ID.findall(main.get_text(" "))))
    kept_cells = 0
    for table in main.find_all("table"):
        # ATT&CK tables: keep ONLY the free-text column ("Use" / "Description"), as paragraphs.
        # The technique-name and ID columns would give the answer away; IOC tables are dropped.
        rows = [[c.get_text(" ", strip=True) for c in tr.find_all(["th", "td"])] for tr in table.find_all("tr")]
        header = next((r for r in rows if r), [])
        col = next((i for i, h in enumerate(header)
                    if re.search(r"\b(use|description|procedure|activit\w*)\b", h, re.I)), None)
        if keep_table_text and col is not None and any(TECH_ID.search(" ".join(r)) for r in rows):
            paragraphs_from_table = [r[col] for r in rows[1:] if len(r) > col and len(r[col].split()) >= 4]
            new = soup.new_tag("div")
            for text in paragraphs_from_table:
                para = soup.new_tag("p")
                para.string = text
                new.append(para)
            kept_cells += len(paragraphs_from_table)
            table.replace_with(new)
        else:
            table.decompose()
    lines = [ln.strip() for ln in main.get_text("\n").split("\n")]
    text = "\n".join(lines)
    text = BRACKETED.sub("", text)
    text = TECH_ID.sub("", text)
    text = re.sub(r"\[\s*,?\s*\]", "", text)                       # leftovers like "[ ], [ ]"
    text = re.sub(r"[ \t]+([.,;:])", r"\1", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    # Inline links split sentences over several lines; join lines that do not end a sentence.
    paragraphs = []
    for block in re.split(r"\n\s*\n", text):
        joined = re.sub(r"\s*\n\s*", " ", block).strip()
        if joined:
            paragraphs.append(joined)
    return {"id": html_path.stem, "title": title, "truth_raw": truth_raw, "table_descriptions_kept": kept_cells,
            "truth": sorted({t.split(".")[0] for t in truth_raw}), "text": "\n\n".join(paragraphs)}


def cmd_prepare(args) -> None:
    args.out.mkdir(parents=True, exist_ok=True)
    rows = []
    for path in sorted(args.raw.glob("*.html")):
        rec = prepare_one(path, keep_table_text=not args.prose_only)
        if len(rec["truth"]) < args.min_truth:
            print(f"skip {rec['id']}: {len(rec['truth'])} technique ids (fewer than {args.min_truth})")
            continue
        leaked = TECH_ID.findall(rec["text"])
        assert not leaked, (rec["id"], leaked[:5])
        (args.out / f"{rec['id']}.txt").write_text(rec["text"], encoding="utf-8")
        rows.append({k: rec[k] for k in ("id", "title", "truth", "truth_raw", "table_descriptions_kept")} | {"characters": len(rec["text"])})
        print(f"{rec['id']}: {len(rec['truth'])} techniques, {rec['table_descriptions_kept']} table descriptions kept, {len(rec['text'])} chars")
    (args.out / "truth.json").write_text(json.dumps(rows, indent=1), encoding="utf-8")


# ------------------------------------------------------------------ leakage
def cmd_leakage(args) -> None:
    from ttp_extraction.data.labels import load_dataset
    from ttp_extraction.inference.segment import split_with_offsets

    texts, _, _ = load_dataset(Path("ThreatMAMBA-main/CTI2TTPs.csv"))
    train = {normalise(t) for t in texts}
    train_long = [normalise(t) for t in texts if len(t) > 60]
    truth = json.loads((args.data / "truth.json").read_text(encoding="utf-8"))
    out = {}
    for rec in truth:
        sentences = [s.text for s in split_with_offsets((args.data / f"{rec['id']}.txt").read_text(encoding="utf-8"))
                     if s.skip_reason is None]
        exact = sum(normalise(s) in train for s in sentences)
        # near-duplicate: a training sentence of 60+ chars contained in the advisory sentence or vice versa
        joined = " || ".join(normalise(s) for s in sentences)
        contained = sum(1 for t in train_long if t in joined)
        out[rec["id"]] = {"sentences": len(sentences), "exact_in_training": exact,
                          "training_sentences_found_inside": contained}
        print(rec["id"], out[rec["id"]], flush=True)
    (args.data / "leakage.json").write_text(json.dumps(out, indent=1), encoding="utf-8")


# ------------------------------------------------------------------ scoring
def prf(pred: set, gold: set) -> dict:
    tp = len(pred & gold)
    p = tp / len(pred) if pred else 0.0
    r = tp / len(gold) if gold else 0.0
    return {"tp": tp, "fp": len(pred - gold), "fn": len(gold - pred), "precision": p, "recall": r,
            "f1": 2 * p * r / (p + r) if p + r else 0.0}


def micro(rows: list[dict]) -> dict:
    tp, fp, fn = (sum(r[k] for r in rows) for k in ("tp", "fp", "fn"))
    p, r = tp / max(tp + fp, 1), tp / max(tp + fn, 1)
    return {"precision": round(100 * p, 1), "recall": round(100 * r, 1),
            "f1": round(100 * 2 * p * r / (p + r), 1) if p + r else 0.0,
            "macro_f1": round(100 * float(np.mean([x["f1"] for x in rows])), 1) if rows else 0.0}


def sentence_probs(predictor, text: str):
    from ttp_extraction.inference.segment import split_with_offsets

    sentences = split_with_offsets(text)
    analysed = [s for s in sentences if s.skip_reason is None]
    probs = predictor.predict([s.text for s in analysed]) if analysed else np.zeros((0, len(predictor.labels)))
    return sentences, probs


def techniques_from(probs, labels, n_tactics, tech_threshold, min_sentences=1) -> set:
    p = probs[:, n_tactics:]
    hits = (p >= tech_threshold).sum(0) if len(p) else np.zeros(len(labels) - n_tactics)
    return {labels[n_tactics + j] for j in np.flatnonzero(hits >= min_sentences)}


THRESHOLDS = (0.9, 0.8, 0.7, 0.6, 0.5, 0.4, 0.3, 0.2, 0.15, 0.1)


def report_probs_for(predictor, data: Path, truth: list[dict], cache_file: Path) -> dict:
    """Sentence probabilities for every report (cached: the model runs once per bundle and variant)."""
    if cache_file.exists():
        stored = np.load(cache_file)
        if all(r["id"] in stored for r in truth):
            return {r["id"]: stored[r["id"]] for r in truth}
    out, timing = {}, {}
    for rec in truth:
        t0 = time.perf_counter()
        _, probs = sentence_probs(predictor, (data / f"{rec['id']}.txt").read_text(encoding="utf-8"))
        timing[rec["id"]] = time.perf_counter() - t0
        out[rec["id"]] = probs
        print(f"  {rec['id']}: {len(probs)} sentences, {timing[rec['id']]:.1f}s", flush=True)
    cache_file.parent.mkdir(parents=True, exist_ok=True)
    np.savez_compressed(cache_file, **out)
    return out


def frequency_baseline(rec_id: str, truth: list[dict], space: set, k: int) -> set:
    """The k techniques that appear most often in the OTHER advisories' answer keys (leave-one-out)."""
    counts = {}
    for other in truth:
        if other["id"] != rec_id:
            for t in other["truth"]:
                if t in space:
                    counts[t] = counts.get(t, 0) + 1
    return set(sorted(counts, key=lambda t: (-counts[t], t))[:k])


def evaluate(probs: dict, truth: list[dict], labels, n_tactics: int, catalog: dict, threshold: float) -> dict:
    space = set(labels[n_tactics:])
    rows, base_rows, tac_rows, detail = [], [], [], []
    for rec in truth:
        p = probs[rec["id"]]
        gold_all = set(rec["truth"])
        gold = gold_all & space
        pred = techniques_from(p, labels, n_tactics, threshold)
        rows.append(prf(pred, gold))
        base_rows.append(prf(frequency_baseline(rec["id"], truth, space, max(1, len(pred))), gold))
        gold_tac = {tac for t in gold_all if t in catalog["techniques"] for tac in catalog["techniques"][t]["tactics"]}
        pred_tac = {labels[j] for j in range(n_tactics) if len(p) and (p[:, j] >= 0.5).any()}
        tac_rows.append(prf(pred_tac, gold_tac))
        names = catalog["techniques"]
        detail.append({"id": rec["id"], "title": rec["title"], "after_attack_v14": rec["id"].startswith(PUBLISHED_AFTER_ATTACK_V14),
                       "sentences": int(len(p)), "gold": len(gold), "gold_outside_label_space": sorted(gold_all - space),
                       **{k: round(v, 3) for k, v in rows[-1].items() if k in ("precision", "recall", "f1")},
                       "tp": rows[-1]["tp"], "fp": rows[-1]["fp"], "fn": rows[-1]["fn"],
                       "baseline_f1": round(base_rows[-1]["f1"], 3), "tactic_f1": round(tac_rows[-1]["f1"], 3),
                       "found": [f"{t} {names.get(t, {}).get('name', '')}" for t in sorted(pred & gold)],
                       "missed": [f"{t} {names.get(t, {}).get('name', '')}" for t in sorted(gold - pred)],
                       "extra": [f"{t} {names.get(t, {}).get('name', '')}" for t in sorted(pred - gold)]})
    return {"threshold": threshold, "techniques": micro(rows), "frequency_baseline": micro(base_rows),
            "tactics": micro(tac_rows), "per_report": detail}


def cmd_score(args) -> None:
    from ttp_api.attack_catalog import load_catalog
    from ttp_extraction.inference.predictor import TTPPredictor

    catalog = load_catalog()
    results = {"note": ("Answer key = ATT&CK ids printed in each CISA advisory (parent techniques). "
                        "Threshold chosen on advisories published before ATT&CK v14 (dev), "
                        "tested on those published after it (test)."), "models": {}}
    for bundle in args.bundle:
        predictor = TTPPredictor.load(bundle, device=args.device, warmup=False)
        labels, n_tactics = predictor.labels, predictor.n_tactics
        version = predictor.manifest.get("version", bundle.name)
        model_res = {"run_id": predictor.manifest.get("run_id"), "members": len(predictor.members), "variants": {}}
        for data in args.data:
            truth = json.loads((data / "truth.json").read_text(encoding="utf-8"))
            print(f"{version} on {data.name}", flush=True)
            t0 = time.perf_counter()
            probs = report_probs_for(predictor, data, truth, args.cache / f"{version}_{data.name}.npz")
            dev = [r for r in truth if not r["id"].startswith(PUBLISHED_AFTER_ATTACK_V14)]
            test = [r for r in truth if r["id"].startswith(PUBLISHED_AFTER_ATTACK_V14)]
            sweep_dev = [{"threshold": t} | evaluate(probs, dev, labels, n_tactics, catalog, t)["techniques"] for t in THRESHOLDS]
            chosen = max(sweep_dev, key=lambda r: (r["f1"], r["threshold"]))["threshold"]
            model_res["variants"][data.name] = {
                "reports": {"all": len(truth), "dev_before_v14": len(dev), "test_after_v14": len(test)},
                "seconds_all_reports": round(time.perf_counter() - t0, 1),
                "sweep_dev": sweep_dev,
                "sweep_all": [{"threshold": t} | evaluate(probs, truth, labels, n_tactics, catalog, t)["techniques"] for t in THRESHOLDS],
                "sweep_test": [{"threshold": t} | evaluate(probs, test, labels, n_tactics, catalog, t)["techniques"] for t in THRESHOLDS],
                "chosen_threshold_on_dev": chosen,
                "test_at_chosen": evaluate(probs, test, labels, n_tactics, catalog, chosen),
                "test_at_0.5": evaluate(probs, test, labels, n_tactics, catalog, 0.5),
                "all_at_chosen": evaluate(probs, truth, labels, n_tactics, catalog, chosen),
                "dev_at_chosen": evaluate(probs, dev, labels, n_tactics, catalog, chosen),
            }
            v = model_res["variants"][data.name]
            print(f"  chosen threshold {chosen}: test F1 {v['test_at_chosen']['techniques']['f1']} "
                  f"(baseline {v['test_at_chosen']['frequency_baseline']['f1']}), all F1 {v['all_at_chosen']['techniques']['f1']}, "
                  f"tactics F1 {v['all_at_chosen']['tactics']['f1']}", flush=True)
        # One threshold for both report variants: best MEAN dev F1 across variants (dev = before ATT&CK v14).
        mean_dev = {t: np.mean([next(r["f1"] for r in v["sweep_dev"] if r["threshold"] == t)
                                for v in model_res["variants"].values()]) for t in THRESHOLDS}
        joint = max(THRESHOLDS, key=lambda t: (mean_dev[t], t))
        model_res["joint_threshold_on_dev"] = joint
        for name, v in model_res["variants"].items():
            truth = json.loads((next(d for d in args.data if d.name == name) / "truth.json").read_text(encoding="utf-8"))
            test = [r for r in truth if r["id"].startswith(PUBLISHED_AFTER_ATTACK_V14)]
            probs = report_probs_for(predictor, next(d for d in args.data if d.name == name), truth,
                                     args.cache / f"{version}_{name}.npz")
            v["test_at_joint"] = evaluate(probs, test, labels, n_tactics, catalog, joint)
            v["all_at_joint"] = evaluate(probs, truth, labels, n_tactics, catalog, joint)
            print(f"  joint threshold {joint} on {name}: test F1 {v['test_at_joint']['techniques']['f1']} "
                  f"(baseline {v['test_at_joint']['frequency_baseline']['f1']}), all F1 {v['all_at_joint']['techniques']['f1']}")
        results["models"][version] = model_res
        del predictor
        import torch
        torch.cuda.empty_cache()
    args.out.write_text(json.dumps(results, indent=1), encoding="utf-8")
    print(f"written {args.out}")


def cmd_to_stix(args) -> None:
    """Package one prepared advisory as a STIX 2.1 bundle: the report text as the report's
    description, CISA's ATT&CK ids as attack-pattern objects. Uploading it to the app shows the
    model's result next to the declared ids (which the model never sees)."""
    import uuid

    rec = next(r for r in json.loads((args.data / "truth.json").read_text(encoding="utf-8")) if r["id"] == args.id)
    text = (args.data / f"{args.id}.txt").read_text(encoding="utf-8")
    ns = uuid.UUID("2f6c0a8e-7d0b-4b8e-9a51-3c1d2e4f5a6b")
    now = "2026-10-13T00:00:00.000Z"
    patterns = [{"type": "attack-pattern", "spec_version": "2.1", "id": f"attack-pattern--{uuid.uuid5(ns, t)}",
                 "created": now, "modified": now, "name": t,
                 "external_references": [{"source_name": "mitre-attack", "external_id": t}]} for t in rec["truth_raw"]]
    report = {"type": "report", "spec_version": "2.1", "id": f"report--{uuid.uuid5(ns, args.id)}",
              "created": now, "modified": now, "published": now, "report_types": ["threat-report"],
              "name": rec["title"], "description": text,
              "object_refs": [p["id"] for p in patterns],
              "external_references": [{"source_name": "cisa", "external_id": args.id.upper(),
                                       "url": f"https://www.cisa.gov/news-events/cybersecurity-advisories/{args.id}"}]}
    bundle = {"type": "bundle", "id": f"bundle--{uuid.uuid5(ns, args.id + 'bundle')}", "objects": [report, *patterns]}
    args.out.write_text(json.dumps(bundle, indent=1, ensure_ascii=False), encoding="utf-8")
    print(f"{args.out}: {len(patterns)} attack-patterns, {len(text)} characters of text")


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("prepare")
    a.add_argument("--raw", type=Path, required=True)
    a.add_argument("--out", type=Path, required=True)
    a.add_argument("--min-truth", type=int, default=8)
    a.add_argument("--prose-only", action="store_true", help="drop every table (strict variant)")
    b = sub.add_parser("leakage")
    b.add_argument("--data", type=Path, required=True)
    c = sub.add_parser("score")
    c.add_argument("--data", type=Path, nargs="+", required=True, help="one or more prepared folders (variants)")
    c.add_argument("--bundle", type=Path, nargs="+", default=[Path("models/ttp-v2")])
    c.add_argument("--device", default="cuda")
    c.add_argument("--cache", type=Path, default=Path("reports/real_report_probs"))
    c.add_argument("--out", type=Path, required=True)
    d = sub.add_parser("to-stix")
    d.add_argument("--data", type=Path, required=True)
    d.add_argument("--id", required=True)
    d.add_argument("--out", type=Path, required=True)
    args = p.parse_args()
    {"prepare": cmd_prepare, "leakage": cmd_leakage, "score": cmd_score, "to-stix": cmd_to_stix}[args.cmd](args)


if __name__ == "__main__":
    main()
