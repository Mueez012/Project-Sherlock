"""Evaluate a trained run: micro / macro P-R-F1, per-label report, decision layer.

Default split is VALIDATION. The test split is only for (a) checking that a
baseline reproduces and (b) the single final report (Phase 9); pass
`--split test` explicitly for those. Every decision-layer setting
(thresholds, hierarchy, top-1) is fitted on validation and applied unchanged.

Examples
  # compare every decision-layer variant on validation (honest, cross-fitted)
  python -m ttp_extraction.evaluation.evaluate --csv ThreatMAMBA-main/CTI2TTPs.csv \
      --seed 0 --run-name concat_seed_0 --compare
  # one setting, per-label CSV, on validation
  python -m ttp_extraction.evaluation.evaluate --csv ... --run-name concat_seed_0 \
      --threshold-mode per_label --hierarchy on --top1 on
  # several runs on the same split, probabilities averaged (seed ensemble)
  python -m ttp_extraction.evaluation.evaluate --csv ... --ensemble a_seed_0,b_seed_0
"""
from __future__ import annotations

import argparse
import csv
import json
from itertools import product
from pathlib import Path

import numpy as np
import torch

from ttp_extraction.data.labels import load_dataset
from ttp_extraction.data.splits import load_split
from ttp_extraction.evaluation.decision import (
    THRESHOLD_MODES, DecisionLayer, cross_fitted_predictions,
)
from ttp_extraction.evaluation.metrics import (
    PAPER, evaluate_label_sets, per_label_rows, quality_summary, support_buckets,
)
from ttp_extraction.securebert.cache import EmbeddingCache, cache_root
from ttp_extraction.training.train import TrainConfig, build_model, evaluate

ROW_AVERAGES = ("micro", "macro_supported_labels", "macro", "weighted", "samples")


_CACHES: dict[str, EmbeddingCache] = {}


def run_split_seed(run_dir: Path) -> int:
    """Split a run was trained on: split.json if present, else its config seed."""
    path = run_dir / "split.json"
    if path.exists():
        return json.loads(path.read_text(encoding="utf-8"))["split_seed"]
    return json.loads((run_dir / "config.json").read_text(encoding="utf-8"))["seed"]


def run_probabilities(run_dir: Path, cache, y, split, device) -> dict[str, np.ndarray]:
    """Validation and test probabilities of one run, cached in the run folder.

    cache=None picks the embedding cache that matches the run's `features`.
    """
    path = run_dir / "probabilities.npz"
    best = run_dir / "best.pt"
    if path.exists() and path.stat().st_mtime >= best.stat().st_mtime:
        stored = np.load(path)
        if all(np.array_equal(stored[f"{s}_idx"], split[s]) for s in ("val", "test")):
            return {s: stored[s] for s in ("val", "test")}
    raw_config = json.loads((run_dir / "config.json").read_text(encoding="utf-8"))
    if "encoder_lr" in raw_config:          # fine-tuned SecureBERT run (train_finetune.py)
        probs = finetune_probabilities(run_dir, raw_config, y, split, device)
        np.savez(path, **probs, val_idx=split["val"], test_idx=split["test"])
        return probs
    config = TrainConfig.from_dict(raw_config)
    if cache is None:
        cache = _CACHES.setdefault(config.features, EmbeddingCache(cache_root(config.features)))
    model = build_model(config, y.shape[1]).to(device)
    model.load_state_dict(torch.load(best, map_location=device))
    probs = {s: evaluate(model, cache, y, split[s], config.batch_size, device)[1]
             for s in ("val", "test")}
    np.savez(path, **probs, val_idx=split["val"], test_idx=split["test"])
    return probs


_TEXTS: list[str] = []


def finetune_probabilities(run_dir: Path, raw_config: dict, y, split, device) -> dict[str, np.ndarray]:
    """Validation and test probabilities of an end-to-end (fine-tuned SecureBERT) run."""
    from transformers import AutoConfig, AutoModel

    from ttp_extraction.classifier.model import TTPExtractorE2E
    from ttp_extraction.preprocessing.tokenization import MODEL_NAME, encode, load_tokenizer
    from ttp_extraction.training.train_finetune import FinetuneConfig, evaluate_e2e

    config = FinetuneConfig(**raw_config)
    if not _TEXTS:
        from ttp_extraction.data.labels import load_dataset
        _TEXTS.extend(load_dataset(Path("ThreatMAMBA-main/CTI2TTPs.csv"))[0])
    encoded = encode(load_tokenizer(), _TEXTS)
    input_ids = torch.from_numpy(encoded["input_ids"])
    attention_mask = torch.from_numpy(encoded["attention_mask"])
    # Weights come from best.pt, so the encoder only needs the right shape.
    encoder = AutoModel.from_config(AutoConfig.from_pretrained(MODEL_NAME))
    model = TTPExtractorE2E(encoder=encoder, n_labels=y.shape[1], d_model=config.d_model,
                            d_state=config.d_state, n_layers=config.n_layers,
                            kernel_size=config.kernel_size, dropout=config.dropout,
                            classifier=config.classifier).to(device)
    model.load_state_dict(torch.load(run_dir / "best.pt", map_location=device, weights_only=True))
    return {s: evaluate_e2e(model, input_ids, attention_mask, y, split[s], 32, device)[1]
            for s in ("val", "test")}


def summary_line(report: dict) -> dict:
    return {f"{slice_}_{avg}_{m}": round(report[slice_][avg][m], 2)
            for slice_ in ("tactics", "techniques")
            for avg in ("micro", "macro_supported_labels") for m in ("precision", "recall", "f1")}


def print_table(report: dict, title: str) -> None:
    print(f"\n{title}")
    print(f"{'slice':<11}{'average':<24}{'P':>7}{'R':>7}{'F1':>7}")
    for name, slice_ in report.items():
        for average in ROW_AVERAGES:
            m = slice_[average]
            print(f"{name:<11}{average:<24}{m['precision']:7.2f}{m['recall']:7.2f}{m['f1']:7.2f}")
        paper = PAPER[name]
        print(f"{name:<11}{'paper (Table VI, micro)':<24}{paper['precision']:7.2f}"
              f"{paper['recall']:7.2f}{paper['f1']:7.2f}")
        print(f"{'':<11}labels {slice_['labels']}, with rows {slice_['labels_with_support']}, "
              f"ever predicted {slice_['labels_ever_predicted']}")


def compare_decisions(y_val, p_val, y_train, n_tactics, folds) -> list[dict]:
    """Every decision-layer variant, scored on validation by cross-fitting."""
    rows = []
    for mode, hierarchy, top1 in product(THRESHOLD_MODES, (False, True), (False, True)):
        args = {"threshold_mode": mode, "hierarchy": hierarchy, "top1": top1}
        pred = cross_fitted_predictions(args, y_val, p_val, n_tactics, y_train, folds)
        layer = DecisionLayer(**args)
        rows.append({"decision": layer.name, **summary_line(evaluate_label_sets(y_val, pred, n_tactics))})
    return rows


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--csv", type=Path, required=True)
    p.add_argument("--cache", type=Path, default=None,
                   help="default: the cache matching each run's features")
    p.add_argument("--splits", type=Path, default=Path("artifacts/splits"))
    p.add_argument("--runs", type=Path, default=Path("runs"))
    p.add_argument("--reports", type=Path, default=Path("reports"))
    p.add_argument("--seed", type=int, default=0, help="split seed")
    p.add_argument("--run-name", default=None, help="default: seed_<seed>")
    p.add_argument("--ensemble", default=None,
                   help="comma-separated run names on the SAME split; probabilities are averaged")
    p.add_argument("--split", choices=("val", "test"), default="val")
    p.add_argument("--threshold-mode", choices=THRESHOLD_MODES, default="fixed")
    p.add_argument("--hierarchy", choices=("off", "on"), default="off")
    p.add_argument("--top1", choices=("off", "on"), default="off")
    p.add_argument("--min-pos", type=int, default=5)
    p.add_argument("--cv-folds", type=int, default=5)
    p.add_argument("--compare", action="store_true",
                   help="score every decision variant on validation (cross-fitted)")
    args = p.parse_args()

    names = args.ensemble.split(",") if args.ensemble else [args.run_name or f"seed_{args.seed}"]
    label = names[0] if len(names) == 1 else "ensemble_" + "+".join(names)

    _, y, vocab = load_dataset(args.csv)
    cache = EmbeddingCache(args.cache) if args.cache else None
    for n in names:
        if run_split_seed(args.runs / n) != args.seed:
            raise SystemExit(f"{n} was trained on split seed {run_split_seed(args.runs / n)}, "
                             f"not {args.seed}; ensembles must share one split")
    split = load_split(args.splits / f"seed_{args.seed}.json")
    n_tactics = len(vocab.tactics)
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    probs = [run_probabilities(args.runs / n, cache, y, split, device) for n in names]
    p_val = np.mean([q["val"] for q in probs], axis=0)
    p_eval = np.mean([q[args.split] for q in probs], axis=0)
    y_train, y_val, y_eval = y[split["train"]], y[split["val"]], y[split[args.split]]
    args.reports.mkdir(parents=True, exist_ok=True)

    if args.compare:
        rows = compare_decisions(y_val, p_val, y_train, n_tactics, args.cv_folds)
        out = args.reports / f"decision_compare_{label}.csv"
        with out.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
            writer.writeheader()
            writer.writerows(rows)
        print(f"validation, {args.cv_folds}-fold cross-fitted decision layer ({label})")
        print(f"{'decision':<24}{'tac micro':>10}{'tac macro':>10}{'tech micro':>11}{'tech macro':>11}"
              f"{'tech P':>8}{'tech R':>8}")
        for r in rows:
            print(f"{r['decision']:<24}{r['tactics_micro_f1']:10.2f}"
                  f"{r['tactics_macro_supported_labels_f1']:10.2f}{r['techniques_micro_f1']:11.2f}"
                  f"{r['techniques_macro_supported_labels_f1']:11.2f}"
                  f"{r['techniques_micro_precision']:8.2f}{r['techniques_micro_recall']:8.2f}")
        print(f"\nwritten to {out}")
        return

    if args.split == "test":
        print("NOTE: scoring the TEST split. Use this only to check a baseline reproduces "
              "or for the final report; never to choose settings.")
    layer = DecisionLayer(args.threshold_mode, args.hierarchy == "on", args.top1 == "on",
                          min_pos=args.min_pos).fit(y_val, p_val, n_tactics, y_train)
    if len(names) == 1:
        layer.save(args.runs / names[0] / f"decision_{layer.name}.json", vocab.labels)
    pred = layer.predict(p_eval)
    report = evaluate_label_sets(y_eval, pred, n_tactics)
    honest = None
    if args.split == "val" and layer.name != "fixed":
        cf = cross_fitted_predictions({"threshold_mode": layer.threshold_mode,
                                       "hierarchy": layer.hierarchy, "top1": layer.top1,
                                       "min_pos": layer.min_pos},
                                      y_val, p_val, n_tactics, y_train, args.cv_folds)
        honest = evaluate_label_sets(y_val, cf, n_tactics)

    supports = {s: y[split[s]].sum(axis=0) for s in ("train", "val", "test")}
    rows = per_label_rows(y_eval, pred, vocab.labels, n_tactics, supports, layer.thresholds)
    tag = f"{label}_{args.split}_{layer.name}"
    with (args.reports / f"per_label_{tag}.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)

    result = {
        "runs": names, "split_seed": args.seed, "split": args.split, "rows": int(len(y_eval)),
        "decision": {"name": layer.name, "threshold_mode": layer.threshold_mode,
                     "hierarchy": layer.hierarchy, "top1": layer.top1,
                     "fitted_on": "validation"},
        "scores": report,
        "validation_cross_fitted": honest,
        "technique_support_buckets": support_buckets(rows, "technique"),
        "label_quality": quality_summary(rows),
        "macro_note": ("macro_supported_labels averages only labels with at least one row in the "
                       "evaluated split; plain macro also counts labels with no rows as F1 = 0."),
        "paper_table_VI": PAPER,
    }
    (args.reports / f"eval_{tag}.json").write_text(json.dumps(result, indent=2), encoding="utf-8")

    print_table(report, f"{label}: {args.split} split ({len(y_eval)} rows), decision {layer.name}")
    if honest:
        print_table(honest, f"same decision layer, {args.cv_folds}-fold cross-fitted on validation "
                            "(honest estimate)")
    print("\ntechnique macro-F1 by training support:")
    for bucket, v in result["technique_support_buckets"].items():
        score = "n/a" if v["macro_f1"] is None else f"{v['macro_f1']:.2f}"
        print(f"  {bucket:>6} train rows: {v['labels']:3d} labels, macro-F1 {score}")
    print("label quality:", json.dumps(result["label_quality"]))
    print(f"\nwritten to {args.reports / f'eval_{tag}.json'} and per_label_{tag}.csv")


if __name__ == "__main__":
    main()
