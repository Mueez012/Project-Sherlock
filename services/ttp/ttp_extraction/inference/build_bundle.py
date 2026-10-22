"""Build a served model bundle (models/ttp-v*/) from finished training runs.

  # one model
  python -m ttp_extraction.inference.build_bundle --run finetune_v2_seed_0 --out models/ttp-v1
  # 2-model ensemble (the final model of FINAL_RESULTS.md): probabilities are averaged
  python -m ttp_extraction.inference.build_bundle --run finetune_v2_seed_0,finetune_v2b_seed_0 \
      --out models/ttp-v2 --version ttp-v2 --default-mode report_tuned

Reads only finished files (never a run that is still training). Checkpoints are
referenced by relative paths in manifest.json instead of copied (they are 500 MB
each); add --copy-checkpoint to copy them. Thresholds for the "per_slice" and
"per_label" modes are fitted on VALIDATION probabilities (averaged over the
ensemble members) with the Phase 2 decision layer.

"report_tuned" (tactics 0.5, techniques --report-technique-threshold) is the
report-level rule chosen by tune_report_rule.py on half of the authors' reports and
checked on the other half (reports/report_rule_tuning*.json).
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
from datetime import datetime, timezone
from pathlib import Path

import numpy as np

from ttp_extraction.inference.predictor import file_sha256, vocab_hash

LABEL_VOCAB = Path("artifacts/label_vocab.json")
DATASET = Path("ThreatMAMBA-main/CTI2TTPs.csv")
FINAL_RESULTS = Path("reports/final_results_with_tuned.json")


def validation_probs(run_dirs: list[Path]):
    """(y_val, mean probability over runs) on the runs' shared validation split."""
    from ttp_extraction.data.labels import load_dataset
    from ttp_extraction.data.splits import load_split
    from ttp_extraction.evaluation.evaluate import run_split_seed

    seeds = {run_split_seed(d) for d in run_dirs}
    if len(seeds) != 1:
        raise SystemExit(f"ensemble members were trained on different splits: {seeds}")
    split = load_split(Path("artifacts/splits") / f"seed_{seeds.pop()}.json")
    probs = []
    for d in run_dirs:
        stored = np.load(d / "probabilities.npz")
        if not np.array_equal(stored["val_idx"], split["val"]):
            raise SystemExit(f"{d}/probabilities.npz does not match the validation split")
        probs.append(stored["val"])
    _, y, _ = load_dataset(DATASET)
    return y[split["val"]], np.mean(probs, axis=0)


def validation_metrics(y_val, p_val, n_tactics: int) -> dict:
    from ttp_extraction.evaluation.metrics import evaluate_predictions

    scores = evaluate_predictions(y_val, p_val, n_tactics, 0.5)
    return {"fixed_0.5": {
        f"{name}_{avg}_f1": round(scores[name][avg]["f1"], 2)
        for name in ("tactics", "techniques") for avg in ("micro", "macro_supported_labels")}}


def test_metrics(runs: list[str]) -> dict | None:
    """Final test results (FINAL_RESULTS.md) for the family and split seed of these runs."""
    if not FINAL_RESULTS.exists():
        return None
    key = ",".join(runs)
    for name, fam in json.loads(FINAL_RESULTS.read_text(encoding="utf-8"))["families"].items():
        if key in fam["runs"]:
            seed = fam["runs"].index(key)
            fixed = fam["test"]["fixed_0.5"]
            return {"family": name, "split_seed": seed,
                    "this_seed_f1_at_0.5": {k: v[seed] for k, v in fixed["per_seed_f1"].items()},
                    "mean_over_3_seeds_at_0.5": {k: fixed[k]["f1"].replace("Â", "") for k in
                                                 ("tactics_micro", "techniques_micro",
                                                  "tactics_macro_supported_labels", "techniques_macro_supported_labels")},
                    "source": str(FINAL_RESULTS)}
    return None


def report_tuning(path: Path) -> dict | None:
    """Held-out agreement of the report-level rules (tune_report_rule.py), if it was run."""
    if not path.exists():
        return None
    data = json.loads(path.read_text(encoding="utf-8"))
    return {"fixed_0.5_held_out": data["current_rule"]["held_out"],
            "report_tuned_held_out": data["best_on_tune"]["held_out"],
            "report_tuned_rule": data["best_on_tune"]["rule"], "reports": data["reports"],
            "source": str(path), "note": data["note"]}


def real_report_eval(path: Path | None, version: str) -> dict | None:
    """Results on real CISA advisories (evaluation/real_reports.py) for this bundle version, if run."""
    if path is None or not path.exists():
        return None
    data = json.loads(path.read_text(encoding="utf-8"))["models"].get(version)
    if not data:
        return None
    out = {"joint_threshold_on_dev": data["joint_threshold_on_dev"], "source": str(path),
           "note": "answer key = ATT&CK ids printed in CISA advisories; threshold chosen on advisories "
                   "published before ATT&CK v14, tested on those published after it"}
    for name, v in data["variants"].items():
        out[name] = {"test_after_v14": v["test_at_joint"]["techniques"],
                     "test_frequency_baseline": v["test_at_joint"]["frequency_baseline"],
                     "all_reports": v["all_at_joint"]["techniques"], "tactics_all": v["all_at_joint"]["tactics"],
                     "reports": v["reports"]}
    return out


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--run", required=True, help="run name, or several separated by commas (ensemble)")
    p.add_argument("--runs", type=Path, default=Path("runs"))
    p.add_argument("--reports", type=Path, default=Path("reports"))
    p.add_argument("--out", type=Path, default=Path("models/ttp-v1"))
    p.add_argument("--version", default="ttp-v1")
    p.add_argument("--default-mode", default="fixed", choices=("fixed", "per_slice", "per_label", "report_tuned"))
    p.add_argument("--report-technique-threshold", type=float, default=0.2,
                   help="technique threshold of the report_tuned mode (see tune_report_rule.py)")
    p.add_argument("--report-tuning", type=Path, default=None,
                   help="tune_report_rule.py output to record (default reports/report_rule_tuning.json)")
    p.add_argument("--real-eval", type=Path, default=None,
                   help="real_reports.py output to record in the manifest (reports/real_reports_eval.json)")
    p.add_argument("--copy-checkpoint", action="store_true")
    args = p.parse_args()

    from ttp_api.attack_catalog import load_catalog

    runs = args.run.split(",")
    run_dirs = [args.runs / r for r in runs]
    summaries, configs = [], []
    for d in run_dirs:
        summary = json.loads((d / "summary.json").read_text(encoding="utf-8"))
        if summary.get("stop_reason") == "in_progress":
            raise SystemExit(f"{d.name} is still training; pick a finished run")
        summaries.append(summary)
        configs.append(json.loads((d / "config.json").read_text(encoding="utf-8")))
    model_type = "finetuned_e2e" if "encoder_lr" in configs[0] else "frozen_head"
    if len(runs) > 1 and model_type != "finetuned_e2e":
        raise SystemExit("ensembles are supported for fine-tuned runs only")
    vocab = json.loads(LABEL_VOCAB.read_text(encoding="utf-8"))
    labels = vocab["tactics"] + vocab["techniques"]
    n_tactics = len(vocab["tactics"])
    args.out.mkdir(parents=True, exist_ok=True)

    shutil.copyfile(run_dirs[0] / "config.json", args.out / "config.json")
    shutil.copyfile(LABEL_VOCAB, args.out / "label_vocab.json")
    from ttp_extraction.evaluation.decision import fit_thresholds

    y_val, p_val = validation_probs(run_dirs)
    tuning_path = args.report_tuning or args.reports / "report_rule_tuning.json"
    thresholds = {"default_mode": args.default_mode, "fixed": 0.5,
                  "fitted_on": f"validation split, mean probability of {', '.join(runs)}",
                  **{m: fit_thresholds(y_val, p_val, n_tactics, m).round(4).tolist() for m in ("per_slice", "per_label")},
                  "report_tuned": [0.5] * n_tactics + [args.report_technique_threshold] * len(vocab["techniques"]),
                  "report_tuned_source": str(tuning_path)}
    (args.out / "thresholds.json").write_text(json.dumps(thresholds), encoding="utf-8")
    catalog = load_catalog()
    tt = {t: catalog["techniques"][t]["tactics"] for t in vocab["techniques"]}
    (args.out / "technique_to_tactics.json").write_text(json.dumps(tt, indent=1), encoding="utf-8")

    checkpoints = []
    for i, d in enumerate(run_dirs):
        if args.copy_checkpoint:
            name = "best.pt" if len(runs) == 1 else f"best_{i}.pt"
            shutil.copyfile(d / "best.pt", args.out / name)
            checkpoints.append(name)
        else:
            checkpoints.append(Path(os.path.relpath(d / "best.pt", args.out)).as_posix())
    files = ["config.json", "label_vocab.json", "thresholds.json", "technique_to_tactics.json"]
    manifest = {
        "name": "ThreatMAMBA-TTP",
        "version": args.version,
        "run_id": "+".join(runs),
        "model_type": model_type,
        "encoder": "ehsanaghaei/SecureBERT",
        "max_length": 160,
        "classifier": configs[0].get("classifier", "concat"),
        "checkpoint": checkpoints[0],
        "threshold_mode": args.default_mode,
        "label_space": {"tactics": n_tactics, "techniques": len(vocab["techniques"])},
        "label_vocab_sha256": vocab_hash(labels),
        "attack_version": catalog["attack_version"],
        "training": summaries[0] if len(runs) == 1 else {r: s for r, s in zip(runs, summaries)},
        "metrics": {
            "validation": validation_metrics(y_val, p_val, n_tactics),
            "test": test_metrics(runs),
            "report_level_agreement": report_tuning(tuning_path),
            "real_cisa_advisories": real_report_eval(args.real_eval, args.version),
        },
        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "sha256": {**{f: file_sha256(args.out / f) for f in files},
                   **{f"checkpoint_{i}": file_sha256(args.out / c) for i, c in enumerate(checkpoints)}},
    }
    if len(runs) > 1:
        manifest["members"] = [{"run_id": r, "checkpoint": c, "config": cfg}
                               for r, c, cfg in zip(runs, checkpoints, configs)]
    (args.out / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(json.dumps({k: manifest[k] for k in ("version", "run_id", "model_type")} | {"metrics": manifest["metrics"]}, indent=2))


if __name__ == "__main__":
    main()
