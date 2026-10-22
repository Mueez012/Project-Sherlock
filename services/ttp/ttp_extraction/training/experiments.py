"""Append-only log of every training run: reports/experiments.csv.

Scores are on the VALIDATION split only, so the log can be used to choose
between runs without touching the test split. Two decision rules are logged,
neither of which is fitted to the data:
  fixed_0.5   the paper's threshold
  top1        threshold 0.5, plus the most probable tactic / technique for any
              sentence that would otherwise get none (Phase 2 finding)
"""
from __future__ import annotations

import csv
import json
import time
from dataclasses import asdict
from pathlib import Path

from ttp_extraction.evaluation.decision import DecisionLayer
from ttp_extraction.evaluation.metrics import evaluate_label_sets

LOG = Path("reports/experiments.csv")
COLUMNS = (
    "timestamp", "run", "preset", "changed", "seed", "epochs_run", "best_epoch",
    "best_val_loss", "val_micro_f1_tactics", "val_macro_f1_tactics",
    "val_micro_f1_techniques", "val_macro_f1_techniques", "threshold_mode",
    "wall_seconds", "config",
    "top1_val_micro_f1_tactics", "top1_val_macro_f1_tactics",
    "top1_val_micro_f1_techniques", "top1_val_macro_f1_techniques", "objective",
)


def append_row(row: dict, path: Path = LOG) -> None:
    """Append one row; if the file has an older header, rewrite it with the new one."""
    path.parent.mkdir(parents=True, exist_ok=True)
    rows = []
    if path.exists():
        with path.open(newline="", encoding="utf-8") as handle:
            reader = csv.DictReader(handle)
            if tuple(reader.fieldnames or ()) != COLUMNS:
                rows = list(reader)
    if rows or not path.exists():
        with path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=COLUMNS)
            writer.writeheader()
            writer.writerows({k: r.get(k, "") for k in COLUMNS} for r in rows)
    with path.open("a", newline="", encoding="utf-8") as handle:
        csv.DictWriter(handle, fieldnames=COLUMNS).writerow({k: row.get(k, "") for k in COLUMNS})


def objective(scores: dict) -> float:
    """Mean of micro-F1 and macro-F1 (supported labels) over tactics and techniques."""
    return sum(scores[s][a]["f1"] for s in ("tactics", "techniques")
               for a in ("micro", "macro_supported_labels")) / 4


def validation_scores(model, sequences, y, split, n_tactics, batch_size) -> dict:
    from ttp_extraction.training.train import evaluate

    device = next(model.parameters()).device
    _, val_prob = evaluate(model, sequences, y, split["val"], batch_size, device)
    y_val = y[split["val"]]
    fixed = evaluate_label_sets(y_val, val_prob > 0.5, n_tactics)
    top1_layer = DecisionLayer("fixed", top1=True).fit(y_val, val_prob, n_tactics)
    top1 = evaluate_label_sets(y_val, top1_layer.predict(val_prob), n_tactics)
    return {"fixed": fixed, "top1": top1}


def log_run(run_name, preset, changed, config, run_dir: Path, model, sequences, y, split,
            n_tactics: int, path: Path = LOG) -> dict:
    """Score the restored best model on validation and append one row."""
    scores = validation_scores(model, sequences, y, split, n_tactics, config.batch_size)
    fixed, top1 = scores["fixed"], scores["top1"]
    summary = json.loads((run_dir / "summary.json").read_text(encoding="utf-8"))
    f = lambda v: f"{v:.2f}"
    row = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "run": run_name, "preset": preset, "changed": changed, "seed": config.seed,
        "epochs_run": summary["epochs_run"], "best_epoch": summary["best_epoch"],
        "best_val_loss": f"{summary['best_val_loss']:.6f}",
        "val_micro_f1_tactics": f(fixed["tactics"]["micro"]["f1"]),
        "val_macro_f1_tactics": f(fixed["tactics"]["macro_supported_labels"]["f1"]),
        "val_micro_f1_techniques": f(fixed["techniques"]["micro"]["f1"]),
        "val_macro_f1_techniques": f(fixed["techniques"]["macro_supported_labels"]["f1"]),
        "threshold_mode": "fixed_0.5",
        "wall_seconds": f"{summary.get('wall_seconds', 0):.0f}",
        "config": json.dumps(asdict(config), sort_keys=True),
        "top1_val_micro_f1_tactics": f(top1["tactics"]["micro"]["f1"]),
        "top1_val_macro_f1_tactics": f(top1["tactics"]["macro_supported_labels"]["f1"]),
        "top1_val_micro_f1_techniques": f(top1["techniques"]["micro"]["f1"]),
        "top1_val_macro_f1_techniques": f(top1["techniques"]["macro_supported_labels"]["f1"]),
        "objective": f(objective(top1)),
    }
    append_row(row, path)
    (run_dir / "val_scores.json").write_text(json.dumps(scores, indent=2), encoding="utf-8")
    return row


def backfill(path: Path = LOG, runs: Path = Path("runs"),
             csv_path: Path = Path("ThreatMAMBA-main/CTI2TTPs.csv")) -> None:
    """Fill in validation columns added after a row was written (e.g. top-1 scores)."""
    import torch

    from ttp_extraction.data.labels import load_dataset
    from ttp_extraction.data.splits import load_split
    from ttp_extraction.evaluation.evaluate import run_split_seed
    from ttp_extraction.securebert.cache import EmbeddingCache, cache_root
    from ttp_extraction.training.train import TrainConfig, build_model

    with path.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    todo = [r for r in rows if not r.get("objective")]
    if not todo:
        print("nothing to backfill")
        return
    _, y, vocab = load_dataset(csv_path)
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    for row in todo:
        run_dir = runs / row["run"]
        config = TrainConfig.from_dict(json.loads((run_dir / "config.json").read_text(encoding="utf-8")))
        model = build_model(config, y.shape[1]).to(device)
        model.load_state_dict(torch.load(run_dir / "best.pt", map_location=device))
        split = load_split(Path("artifacts/splits") / f"seed_{run_split_seed(run_dir)}.json")
        cache = EmbeddingCache(cache_root(config.features))
        scores = validation_scores(model, cache, y, split, len(vocab.tactics), config.batch_size)
        top1 = scores["top1"]
        row.update({
            "top1_val_micro_f1_tactics": f"{top1['tactics']['micro']['f1']:.2f}",
            "top1_val_macro_f1_tactics": f"{top1['tactics']['macro_supported_labels']['f1']:.2f}",
            "top1_val_micro_f1_techniques": f"{top1['techniques']['micro']['f1']:.2f}",
            "top1_val_macro_f1_techniques": f"{top1['techniques']['macro_supported_labels']['f1']:.2f}",
            "objective": f"{objective(top1):.2f}",
        })
        if not row.get("config"):
            row["config"] = json.dumps(asdict(config), sort_keys=True)
        (run_dir / "val_scores.json").write_text(json.dumps(scores, indent=2), encoding="utf-8")
        print(f"backfilled {row['run']}: objective {row['objective']}")
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=COLUMNS)
        writer.writeheader()
        writer.writerows({k: r.get(k, "") for k in COLUMNS} for r in rows)


if __name__ == "__main__":
    backfill()
