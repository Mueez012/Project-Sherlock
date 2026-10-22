"""Phase 9: the single final evaluation on the TEST split.

For each model family (e.g. paper-preset frozen, tuned frozen, fine-tuned,
fine-tuned 2-model ensemble) the decision layer is chosen ON VALIDATION ONLY:
the variant with the best mean cross-fitted validation objective over the
three split seeds. Only then are test scores computed, once, and reported as
mean +- std over split seeds 0/1/2, with and without the decision layer.

  python -m ttp_extraction.evaluation.final_report --families configs/final_families.json
"""
from __future__ import annotations

import argparse
import json
from itertools import product
from pathlib import Path

import numpy as np
import torch

from ttp_extraction.data.labels import load_dataset
from ttp_extraction.data.splits import load_split
from ttp_extraction.evaluation.decision import DecisionLayer, cross_fitted_predictions
from ttp_extraction.evaluation.evaluate import run_probabilities
from ttp_extraction.evaluation.metrics import PAPER, evaluate_label_sets
from ttp_extraction.training.experiments import objective

DECISIONS = [f"{m}{'+top1' if t else ''}" for m, t in product(("fixed", "global", "per_slice"), (False, True))]
METRICS = [(s, a) for s in ("tactics", "techniques") for a in ("micro", "macro_supported_labels")]


def layer_args(name: str) -> dict:
    mode, *rules = name.split("+")
    return {"threshold_mode": mode, "hierarchy": "hier" in rules, "top1": "top1" in rules}


def mean_std(values) -> str:
    return f"{np.mean(values):.2f} ± {np.std(values):.2f}"


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--csv", type=Path, default=Path("ThreatMAMBA-main/CTI2TTPs.csv"))
    p.add_argument("--families", type=Path, required=True,
                   help='JSON {"family": ["run_s0[,partner_s0]", "run_s1", "run_s2"], ...}')
    p.add_argument("--runs", type=Path, default=Path("runs"))
    p.add_argument("--out", type=Path, default=Path("reports/final_results.json"))
    args = p.parse_args()

    families = json.loads(args.families.read_text(encoding="utf-8"))
    _, y, vocab = load_dataset(args.csv)
    n_tactics = len(vocab.tactics)
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    result = {"paper_table_VI": PAPER, "families": {}}

    for family, per_seed in families.items():
        probs, splits = [], []
        for seed, runs in enumerate(per_seed):
            split = load_split(Path("artifacts/splits") / f"seed_{seed}.json")
            members = [run_probabilities(args.runs / r, None, y, split, device) for r in runs.split(",")]
            probs.append({s: np.mean([m[s] for m in members], axis=0) for s in ("val", "test")})
            splits.append(split)

        # 1. choose the decision layer on validation (cross-fitted), mean over seeds
        val_objective = {}
        for name in DECISIONS:
            scores = []
            for prob, split in zip(probs, splits):
                y_val = y[split["val"]]
                pred = cross_fitted_predictions(layer_args(name), y_val, prob["val"], n_tactics,
                                                y[split["train"]])
                scores.append(objective(evaluate_label_sets(y_val, pred, n_tactics)))
            val_objective[name] = float(np.mean(scores))
        chosen = max(val_objective, key=val_objective.get)

        # 2. test, once: paper threshold and chosen decision layer (fitted on full validation)
        test = {"fixed_0.5": [], chosen: []}
        for prob, split in zip(probs, splits):
            y_val, y_test = y[split["val"]], y[split["test"]]
            test["fixed_0.5"].append(evaluate_label_sets(y_test, prob["test"] > 0.5, n_tactics))
            layer = DecisionLayer(**layer_args(chosen)).fit(y_val, prob["val"], n_tactics, y[split["train"]])
            test[chosen].append(evaluate_label_sets(y_test, layer.predict(prob["test"]), n_tactics))

        summary = {}
        for decision, reports in test.items():
            summary[decision] = {
                f"{s}_{a}": {m: mean_std([r[s][a][m] for r in reports]) for m in ("precision", "recall", "f1")}
                for s, a in METRICS
            }
            summary[decision]["per_seed_f1"] = {f"{s}_{a}": [round(r[s][a]["f1"], 2) for r in reports]
                                               for s, a in METRICS}
        result["families"][family] = {"runs": per_seed, "validation_objective_by_decision": val_objective,
                                      "chosen_decision": chosen, "test": summary}
        print(f"\n== {family}  (decision chosen on validation: {chosen})")
        for decision, s in summary.items():
            print(f"  {decision:<16}" + "  ".join(f"{k}: F1 {v['f1']}" for k, v in s.items() if k != "per_seed_f1"))

    args.out.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\nwritten to {args.out}")


if __name__ == "__main__":
    main()
