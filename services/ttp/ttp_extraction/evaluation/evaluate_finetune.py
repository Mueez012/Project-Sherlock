"""Evaluate a fine-tuned model on its test split and compare with Table VI.

Automatically determines the best threshold from the validation set,
and reports results for both the best threshold and 0.5.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import torch
import numpy as np
import pandas as pd
from transformers import AutoModel, AutoTokenizer

from ttp_extraction.classifier.model import TTPExtractorE2E
from ttp_extraction.data.labels import load_dataset
from ttp_extraction.data.splits import load_split
from ttp_extraction.evaluation.metrics import PAPER, evaluate_predictions
from ttp_extraction.preprocessing.tokenization import MODEL_NAME, encode
from ttp_extraction.training.train_finetune import FinetuneConfig, evaluate_e2e
from ttp_extraction.data.audit import pick_text_column, classify_columns

SWEEP = (0.2, 0.3, 0.4, 0.5, 0.6)

def summary_or_history(run_dir: Path) -> dict:
    """summary.json if the run finished; otherwise rebuild it from history.json.

    The interrupted finetune_seed_0 run never wrote summary.json.
    """
    path = run_dir / "summary.json"
    if path.exists():
        return json.loads(path.read_text(encoding="utf-8"))
    history = json.loads((run_dir / "history.json").read_text(encoding="utf-8"))
    best = min(history, key=lambda r: r["val_loss"])
    return {"epochs_run": len(history), "best_epoch": best["epoch"],
            "best_val_loss": best["val_loss"], "stop_reason": "interrupted (no summary.json)",
            "finetuned": True}


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--csv", type=Path, required=True)
    p.add_argument("--splits", type=Path, default=Path("artifacts/splits"))
    p.add_argument("--runs", type=Path, default=Path("runs"))
    p.add_argument("--reports", type=Path, default=Path("reports"))
    p.add_argument("--seed", type=int, default=0)
    p.add_argument("--run-name", default=None)
    args = p.parse_args()

    run_name = args.run_name or f"finetune_seed_{args.seed}"
    run_dir = args.runs / run_name
    config = FinetuneConfig(**json.loads((run_dir / "config.json").read_text(encoding="utf-8")))
    summary = summary_or_history(run_dir)

    df = pd.read_csv(args.csv, encoding="gb18030", low_memory=False)
    df.columns = [str(c).strip() for c in df.columns]
    text_col = pick_text_column(classify_columns(df.columns)["other"])
    texts = df[text_col].astype(str).tolist()
    
    _, y, vocab = load_dataset(args.csv)
    split = load_split(args.splits / f"seed_{args.seed}.json")
    n_tactics = len(vocab.tactics)

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    
    print(f"Tokenizing {len(texts)} sentences...")
    tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
    encoded = encode(tokenizer, texts)
    input_ids = torch.from_numpy(encoded["input_ids"])
    attention_mask = torch.from_numpy(encoded["attention_mask"])
    
    print(f"Loading base {MODEL_NAME} for weights restoration...")
    encoder = AutoModel.from_pretrained(MODEL_NAME)
    model = TTPExtractorE2E(
        encoder=encoder, n_labels=y.shape[1], d_model=config.d_model,
        d_state=config.d_state, n_layers=config.n_layers, kernel_size=config.kernel_size,
        dropout=config.dropout, classifier=config.classifier
    ).to(device)
    
    print(f"Loading checkpoint from {run_dir / 'best.pt'}...")
    model.load_state_dict(torch.load(run_dir / "best.pt", map_location=device, weights_only=True))

    print("Evaluating...")
    test_loss, test_prob = evaluate_e2e(model, input_ids, attention_mask, y, split["test"], config.batch_size * 2, device)
    val_loss, val_prob = evaluate_e2e(model, input_ids, attention_mask, y, split["val"], config.batch_size * 2, device)
    
    sweep = {
        t: {name: r["micro"]["f1"] for name, r in
            evaluate_predictions(y[split["val"]], val_prob, n_tactics, t).items()}
        for t in SWEEP
    }
    
    # Pick the best threshold based on validation techniques F1
    best_t = max(sweep.keys(), key=lambda t: sweep[t]["techniques"])
    print(f"Best threshold selected from validation set: {best_t} (Techniques F1: {sweep[best_t]['techniques']:.2f})")
    
    test_05 = evaluate_predictions(y[split["test"]], test_prob, n_tactics, 0.5)
    test_best = evaluate_predictions(y[split["test"]], test_prob, n_tactics, best_t)

    report = {
        "seed": args.seed, "training": summary, "test_rows": int(len(split["test"])), 
        "test_loss": test_loss, "val_loss": val_loss,
        "test_at_0.5": test_05,
        "best_threshold": best_t,
        "test_at_best_threshold": test_best,
        "paper_table_VI": PAPER, "validation_threshold_sweep_micro_f1": sweep
    }
    args.reports.mkdir(parents=True, exist_ok=True)
    out = args.reports / f"eval_{run_name}.json"
    out.write_text(json.dumps(report, indent=2), encoding="utf-8")

    print(f"\nrun: {run_dir}  training: {summary}")
    print(f"test rows: {len(split['test'])}  test loss: {test_loss:.4f}  val loss: {val_loss:.4f}\n")
    
    print(f"--- Results at BEST threshold ({best_t}) ---")
    print(f"{'slice':<11}{'average':<24}{'P':>7}{'R':>7}{'F1':>7}")
    for name, slice_ in test_best.items():
        for average in ("micro", "macro", "macro_supported_labels", "weighted", "samples"):
            m = slice_[average]
            print(f"{name:<11}{average:<24}{m['precision']:7.2f}{m['recall']:7.2f}{m['f1']:7.2f}")
        paper = PAPER[name]
        print(f"{name:<11}{'paper (Table VI)':<24}{paper['precision']:7.2f}"
              f"{paper['recall']:7.2f}{paper['f1']:7.2f}")
        print(f"{'':<11}labels {slice_['labels']}, with test rows {slice_['labels_with_support']}, "
              f"ever predicted {slice_['labels_ever_predicted']}\n")
              
    print("\nvalidation micro-F1 by threshold (diagnostic only):")
    for t, scores in sweep.items():
        print(f"  {t}: tactics {scores['tactics']:.2f}  techniques {scores['techniques']:.2f}")
    print(f"\nwritten to {out}")

if __name__ == "__main__":
    main()
