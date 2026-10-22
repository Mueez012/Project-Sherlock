"""Tune the REPORT-level decision rule against the authors' report TTP lists (held-out check).

  python -m ttp_extraction.inference.tune_report_rule --run finetune_v2_seed_0

Uses the cached sentence embeddings from `extract_report --batch authors` (only the
small head is re-run, on CPU). The 944 reports are split in half by a fixed seed:
every rule is scored on the TUNE half, the best one is then reported on the HELD-OUT
half, which played no part in the choice.

Rules searched: technique threshold, minimum evidence sentences, strong-sentence
override, and which sentences are skipped (IOC lists / very short / headings).
The authors' lists come from a different extractor, so this optimises AGREEMENT
with them, not accuracy against ground truth. Results: reports/report_rule_tuning.json.
"""
from __future__ import annotations

import argparse
import json
from itertools import product
from pathlib import Path

import numpy as np
import pandas as pd
import torch

from ttp_extraction.inference.extract_report import AUTHORS_TTP, EMBEDDING_ROOT, flatten
from ttp_extraction.inference.segment import split_with_offsets


def report_probs(model, embeddings: list[np.ndarray], batch: int = 64) -> np.ndarray:
    from ttp_extraction.data.batching import pad_batch

    out = np.zeros((len(embeddings), model.classifier.linear.out_features), dtype=np.float32)
    order = np.argsort([len(e) for e in embeddings], kind="stable")
    with torch.inference_mode():
        for s in range(0, len(order), batch):
            idx = order[s : s + batch]
            x, m = pad_batch([embeddings[i].astype(np.float32) for i in idx])
            out[idx] = model(x, m)["probabilities"].numpy()
    return out


def score(records, rule, n_tactics, labels) -> dict:
    thr, k, strong, skip = rule
    tp = fp = fn = 0
    jacc = []
    for rec in records:
        keep = rec["keep"][skip]
        p = rec["probs"][keep][:, n_tactics:]
        if len(p):
            hits = (p >= thr).sum(0)
            best = p.max(0)
            on = (hits >= k) | ((hits >= 1) & (best >= strong if strong else False))
        else:
            on = np.zeros(len(labels) - n_tactics, bool)
        ours = {labels[n_tactics + j] for j in np.flatnonzero(on)}
        a, b, c = len(ours & rec["theirs"]), len(ours - rec["theirs"]), len(rec["theirs"] - ours)
        tp, fp, fn = tp + a, fp + b, fn + c
        jacc.append(a / (a + b + c) if a + b + c else 1.0)
    P, R = tp / max(tp + fp, 1), tp / max(tp + fn, 1)
    return {"precision": round(100 * P, 1), "recall": round(100 * R, 1),
            "f1": round(100 * 2 * P * R / (P + R), 1) if P + R else 0.0,
            "jaccard": round(float(np.mean(jacc)), 3),
            "ours_per_report": round((tp + fp) / len(records), 1)}


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--run", default="finetune_v2_seed_0")
    p.add_argument("--bundle", type=Path, default=Path("models/ttp-v1"))
    p.add_argument("--seed", type=int, default=0)
    p.add_argument("--out", type=Path, default=Path("reports/report_rule_tuning.json"))
    p.add_argument("--live", action="store_true",
                   help="run the whole bundle (e.g. an ensemble) on every report instead of the "
                        "single-model embedding cache; probabilities are cached in reports/report_probs/")
    p.add_argument("--device", default="cpu")
    args = p.parse_args()

    torch.set_num_threads(6)
    from ttp_extraction.inference.predictor import TTPPredictor

    predictor = TTPPredictor.load(args.bundle, device=args.device, warmup=False)
    labels, n_tactics = predictor.labels, predictor.n_tactics
    space = set(labels[n_tactics:])
    df = pd.read_csv(AUTHORS_TTP).drop_duplicates("original_index").set_index("original_index")
    cache = EMBEDDING_ROOT / args.run / "authors"
    # Same report order as the cache listing (file names sorted as text), so the tune/held-out
    # split is identical in both modes.
    ids = sorted((int(x.stem) for x in cache.glob("*.npz")), key=str) if not args.live else sorted(df.index, key=str)
    live_cache = Path("reports/report_probs") / f"{predictor.manifest.get('version', 'bundle')}.npz"
    live_probs = dict(np.load(live_cache)) if args.live and live_cache.exists() else {}
    records = []
    for k, rid in enumerate(ids):
        sentences = split_with_offsets(str(df.loc[rid, "Context"]))
        if args.live:
            key = str(rid)
            if key not in live_probs:
                live_probs[key] = predictor.predict([s.text for s in sentences]) if sentences \
                    else np.zeros((0, len(labels)), np.float32)
            if k % 100 == 0:
                print(f"  {k}/{len(ids)} reports", flush=True)
            embeddings = None
        else:
            stored = np.load(cache / f"{rid}.npz")
            flat, offsets = stored["flat"], stored["offsets"]
            embeddings = [flat[offsets[i] : offsets[i + 1]] for i in range(len(offsets) - 1)]
            if len(sentences) != len(embeddings):
                continue                                   # cache made with another splitter version
        reasons = [s.skip_reason for s in sentences]
        keep = {
            "none": np.ones(len(reasons), bool),
            "ioc_short": np.array([r not in ("ioc_list", "short") for r in reasons]),
            "ioc_short_heading": np.array([r is None for r in reasons]),
        }
        theirs = {str(t).split(".")[0] for t in flatten(json.loads(df.loc[rid, "TTPs"]))} & space
        if args.live:
            probs = live_probs[str(rid)]
        else:
            probs = report_probs(predictor.model, embeddings) if embeddings else np.zeros((0, len(labels)))
        records.append({"id": rid, "probs": probs, "keep": keep, "theirs": theirs})
    if args.live:
        live_cache.parent.mkdir(parents=True, exist_ok=True)
        np.savez_compressed(live_cache, **live_probs)
    rng = np.random.default_rng(args.seed)
    order = rng.permutation(len(records))
    tune = [records[i] for i in order[: len(order) // 2]]
    hold = [records[i] for i in order[len(order) // 2 :]]

    grid = list(product((0.6, 0.5, 0.4, 0.3, 0.2, 0.15), (1, 2), (None, 0.9),
                        ("none", "ioc_short", "ioc_short_heading")))
    rows = [{"threshold": t, "min_sentences": k, "strong": s, "skip": sk,
             **score(tune, (t, k, s, sk), n_tactics, labels)} for t, k, s, sk in grid]
    rows.sort(key=lambda r: -r["f1"])
    best = rows[0]
    current = (0.5, 1, None, "ioc_short_heading")
    best_rule = (best["threshold"], best["min_sentences"], best["strong"], best["skip"])
    result = {
        "reports": {"tune": len(tune), "held_out": len(hold), "skipped_cache_mismatch": 944 - len(records)},
        "current_rule": {"rule": current, "tune": score(tune, current, n_tactics, labels),
                         "held_out": score(hold, current, n_tactics, labels)},
        "best_on_tune": {"rule": best_rule, "tune": {k: best[k] for k in ("precision", "recall", "f1", "jaccard", "ours_per_report")},
                         "held_out": score(hold, best_rule, n_tactics, labels)},
        "top10_on_tune": rows[:10],
        "note": "agreement with the authors' report TTP lists, not ground truth",
    }
    args.out.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps({k: v for k, v in result.items() if k != "top10_on_tune"}, indent=2))
    for r in rows[:10]:
        print(r)


if __name__ == "__main__":
    main()
