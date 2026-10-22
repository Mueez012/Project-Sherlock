"""Phase 5: hyperparameter search with Optuna (TPE sampler, median pruner).

Split seed 0 only. Every number the search sees is from the VALIDATION split.
Objective = mean of micro-F1 and macro-F1 (supported labels) over tactics and
techniques, after the decision layer (default: fixed 0.5 threshold + top-1,
which needs no fitting; with a fitted layer the score is cross-fitted).

The study lives in reports/optuna.db, so stopping and re-running the same
command continues where it left off. The best trial is written to
configs/tuned.json, which `train.py --preset tuned` loads.

  python -m ttp_extraction.training.search --trials 30 --max-epochs 60
  python -m ttp_extraction.training.search --report      # importances, best config
"""
from __future__ import annotations

import argparse
import json
import shutil
from dataclasses import asdict, replace
from pathlib import Path

import numpy as np

from ttp_extraction.training.train import TUNED_CONFIG, TrainConfig, changed_fields

STUDY = "threatmamba_seed0"
STORAGE = "sqlite:///reports/optuna.db"

# Plain-English names for the importance printout.
EXPLAIN = {
    "lr": "learning rate (step size of each update)",
    "weight_decay": "weight decay (pull weights toward zero; fights overfitting)",
    "dropout": "dropout inside the S6 layers",
    "input_dropout": "dropout on the SecureBERT features",
    "loss": "loss function (bce / focal / asl)",
    "pos_weight_cap": "extra weight on rare-label positives",
    "d_model": "size of the hidden vectors (SSM Dim)",
    "d_state": "SSM state size",
    "covariance": "full vs diagonal Gaussian covariance",
    "activation": "sigmoid vs SiLU activation",
    "patience": "early-stopping patience",
    "batch_size": "batch size",
    "asl_gamma_neg": "how hard ASL down-weights easy negatives",
    "focal_gamma": "how hard focal loss down-weights easy examples",
}


def suggest(trial, base: TrainConfig) -> TrainConfig:
    """Search space, narrowed by the single-change runs (seed 0, validation):
    learning rate (1e-3: +2.8 objective), input dropout (+1.6) and rare-label
    oversampling (+0.5) helped; weight decay, dropout, token dropout and grad
    clipping did not. Losses other than BCE need F1-based early stopping.
    """
    loss = trial.suggest_categorical("loss", ["bce", "focal", "asl"])
    values = {
        "lr": trial.suggest_float("lr", 2e-4, 3e-3, log=True),
        "dropout": trial.suggest_float("dropout", 0.0, 0.3),
        "input_dropout": trial.suggest_float("input_dropout", 0.0, 0.4),
        "sampler": trial.suggest_categorical("sampler", ["random", "rare_oversample"]),
        "loss": loss,
        "d_model": trial.suggest_categorical("d_model", [48, 64, 96]),
        "d_state": trial.suggest_categorical("d_state", [4, 8, 16]),
        "covariance": trial.suggest_categorical("covariance", ["full", "diagonal"]),
        "activation": trial.suggest_categorical("activation", ["sigmoid", "silu"]),
        "patience": trial.suggest_categorical("patience", [5, 10]),
        "batch_size": trial.suggest_categorical("batch_size", [16, 32]),
        "pos_weight": trial.suggest_categorical("pos_weight", ["none", "sqrt"]),
    }
    # Losses other than BCE must stop on F1 (their val BCE is meaningless); for BCE it is searched.
    values["early_stop_metric"] = (trial.suggest_categorical("early_stop_metric", ["val_loss", "val_micro_f1"])
                                   if loss == "bce" else "val_micro_f1")
    if values["pos_weight"] != "none":
        values["pos_weight_cap"] = trial.suggest_float("pos_weight_cap", 2.0, 20.0, log=True)
    if loss == "focal":
        values["focal_gamma"] = trial.suggest_float("focal_gamma", 0.5, 3.0)
    if loss == "asl":
        values["asl_gamma_neg"] = trial.suggest_float("asl_gamma_neg", 1.0, 5.0)
    return replace(base, **values)


def score(model, sequences, y, split, n_tactics, batch_size, decision: str) -> float:
    from ttp_extraction.evaluation.decision import cross_fitted_predictions
    from ttp_extraction.evaluation.metrics import evaluate_label_sets
    from ttp_extraction.training.experiments import objective
    from ttp_extraction.training.train import evaluate

    device = next(model.parameters()).device
    _, prob = evaluate(model, sequences, y, split["val"], batch_size, device)
    y_val = y[split["val"]]
    mode, *rules = decision.split("+")
    args = {"threshold_mode": mode, "hierarchy": "hier" in rules, "top1": "top1" in rules}
    pred = cross_fitted_predictions(args, y_val, prob, n_tactics, y[split["train"]])
    return objective(evaluate_label_sets(y_val, pred, n_tactics))


def run_search(args) -> None:
    import optuna
    import torch

    from ttp_extraction.data.batching import DeviceSequences
    from ttp_extraction.data.labels import load_dataset
    from ttp_extraction.data.splits import load_split
    from ttp_extraction.securebert.cache import DEFAULT_ROOT, EmbeddingCache
    from ttp_extraction.training.experiments import log_run
    from ttp_extraction.training.train import fit

    _, y, vocab = load_dataset(args.csv)
    split = load_split(args.splits / "seed_0.json")
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    cache = EmbeddingCache(DEFAULT_ROOT)
    sequences = DeviceSequences(cache, device) if device.type == "cuda" else cache
    n_tactics = len(vocab.tactics)
    base = TrainConfig(seed=0, max_epochs=args.max_epochs)

    def objective_fn(trial) -> float:
        config = suggest(trial, base)
        run_dir = args.runs / f"search_trial_{trial.number:03d}"

        def report(record):
            # Cheap per-epoch proxy for pruning: mean of the four val F1s at 0.5.
            value = 100 * np.mean([record["val_f1_tactics"], record["val_f1_techniques"],
                                   record["val_macro_f1_tactics"], record["val_macro_f1_techniques"]])
            trial.report(value, record["epoch"])
            if trial.should_prune():
                raise optuna.TrialPruned()

        try:
            model, history = fit(sequences, y, split, config, run_dir, n_tactics=n_tactics,
                                 device=device, log=lambda _: None, on_epoch=report)
        except optuna.TrialPruned:
            shutil.rmtree(run_dir, ignore_errors=True)
            raise
        value = score(model, sequences, y, split, n_tactics, config.batch_size, args.decision)
        log_run(run_dir.name, "search", json.dumps(changed_fields(config)), config, run_dir,
                model, sequences, y, split, n_tactics)
        trial.set_user_attr("config", asdict(config))
        trial.set_user_attr("epochs", len(history))
        print(f"trial {trial.number}: objective {value:.2f}  epochs {len(history)}  "
              f"{changed_fields(config)}", flush=True)
        for leftover in ("last.pt",):          # keep best.pt, drop the resume checkpoint
            (run_dir / leftover).unlink(missing_ok=True)
        return value

    study = optuna.create_study(
        study_name=STUDY, storage=STORAGE, direction="maximize", load_if_exists=True,
        sampler=optuna.samplers.TPESampler(seed=0),
        pruner=optuna.pruners.MedianPruner(n_startup_trials=5, n_warmup_steps=15),
    )
    if not study.trials:   # start from the best single-change combination (combo B)
        study.enqueue_trial({"loss": "bce", "lr": 1e-3, "dropout": 0.1, "input_dropout": 0.2,
                             "sampler": "rare_oversample", "d_model": 48, "d_state": 4,
                             "covariance": "full", "activation": "sigmoid", "patience": 10,
                             "batch_size": 32, "pos_weight": "none", "early_stop_metric": "val_micro_f1"})
    remaining = args.trials - len([t for t in study.trials if t.state.is_finished()])
    print(f"study {STUDY}: {len(study.trials)} trials so far, running {max(remaining, 0)} more")
    if remaining > 0:
        # A crashed trial is recorded as failed and the search continues.
        study.optimize(objective_fn, n_trials=remaining, gc_after_trial=True, catch=(Exception,))
    write_best(study)


def write_best(study) -> None:
    import optuna

    best = study.best_trial
    config = TrainConfig.from_dict({**best.user_attrs["config"], "max_epochs": 100})
    TUNED_CONFIG.parent.mkdir(parents=True, exist_ok=True)
    TUNED_CONFIG.write_text(json.dumps(asdict(config), indent=2), encoding="utf-8")
    print(f"\nbest trial {best.number}: objective {best.value:.2f}")
    print(f"changes from the paper preset: {changed_fields(config)}")
    print(f"written to {TUNED_CONFIG} (max_epochs reset to 100 for final training)")
    try:
        importance = optuna.importance.get_param_importances(study)
    except Exception as error:             # needs enough finished trials
        print(f"(importances not available yet: {error})")
        return
    print("\nWhich settings mattered most (share of the objective's variation they explain):")
    for name, value in importance.items():
        print(f"  {value:5.1%}  {name:<15} {EXPLAIN.get(name, '')}")


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--csv", type=Path, default=Path("ThreatMAMBA-main/CTI2TTPs.csv"))
    p.add_argument("--splits", type=Path, default=Path("artifacts/splits"))
    p.add_argument("--runs", type=Path, default=Path("runs/search"))
    p.add_argument("--trials", type=int, default=30, help="total finished trials wanted")
    p.add_argument("--max-epochs", type=int, default=60)
    p.add_argument("--decision", default="fixed+top1",
                   help="decision layer used for the objective, e.g. fixed+top1, per_slice+top1")
    p.add_argument("--report", action="store_true", help="only print the best trial and importances")
    args = p.parse_args()
    if args.report:
        import optuna
        write_best(optuna.load_study(study_name=STUDY, storage=STORAGE))
        return
    run_search(args)


if __name__ == "__main__":
    main()
