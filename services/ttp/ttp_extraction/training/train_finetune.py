"""End-to-end fine-tuning of SecureBERT + TTP extraction head. BEYOND THE PAPER.

This uses a differential learning rate (slower for encoder, faster for head),
AdamW with weight decay, mixed precision (FP16), and focal loss for rare techniques.

Each batch is cut to its longest sentence (the dataset is padded to 138
tokens but the average sentence has about 21), which gives the same results
several times faster. Resume state (about 1.5 GB: weights plus AdamW moments)
is written outside OneDrive, under ~/ttp_cache/finetune_state/<run>/.

  python -m ttp_extraction.training.train_finetune --csv ThreatMAMBA-main/CTI2TTPs.csv --seed 0
  ... --resume                     continue an interrupted run exactly
  ... --warm-start-from-best       continue an old run that has only best.pt (approximate:
                                   AdamW moments restart from zero)
  ... --unfreeze-top 4             train only the top 4 SecureBERT layers
"""
from __future__ import annotations

import argparse
import json
import math
import time
from dataclasses import asdict, dataclass
from pathlib import Path

import numpy as np
import torch
import torch.nn.functional as F
from torch.optim import AdamW

from transformers import AutoModel, AutoTokenizer

from ttp_extraction.classifier.model import CLASSIFIERS, TTPExtractorE2E
from ttp_extraction.data.labels import load_dataset
from ttp_extraction.data.splits import load_split
from ttp_extraction.preprocessing.tokenization import MODEL_NAME, encode
from ttp_extraction.training.focal_loss import FocalBCEWithLogitsLoss, compute_pos_weight
from ttp_extraction.training.train import (
    EarlyStopping, macro_f1_supported, micro_f1, rng_state, set_rng_state,
)

STATE_ROOT = Path.home() / "ttp_cache" / "finetune_state"


@dataclass
class FinetuneConfig:
    seed: int = 0
    d_model: int = 48
    d_state: int = 4
    n_layers: int = 3
    kernel_size: int = 4
    dropout: float = 0.1
    classifier: str = "concat"
    encoder_lr: float = 2e-5
    head_lr: float = 1e-4
    weight_decay: float = 1e-2
    batch_size: int = 8
    gradient_accumulation: int = 4
    max_epochs: int = 30
    patience: int = 5
    focal_gamma: float = 2.0
    use_pos_weight: bool = True
    warmup_ratio: float = 0.1
    unfreeze_top: int = -1          # -1: train all of SecureBERT; N: only its top N layers


def batches(indices: np.ndarray, batch_size: int):
    for start in range(0, len(indices), batch_size):
        yield indices[start : start + batch_size]


def trim(input_ids: torch.Tensor, attention_mask: torch.Tensor):
    """Drop padding columns beyond the longest sentence in this batch (right padding)."""
    n = int(attention_mask.sum(dim=1).max())
    return input_ids[:, :n], attention_mask[:, :n]


@torch.no_grad()
def evaluate_e2e(model, input_ids, attention_mask, y, indices, batch_size: int, device):
    """Return (mean BCE loss, probabilities of shape (len(indices), L))."""
    model.eval()
    total, probabilities = 0.0, []
    for idx in batches(indices, batch_size):
        b_ids, b_mask = trim(input_ids[idx], attention_mask[idx])
        b_ids, b_mask = b_ids.to(device), b_mask.to(device)
        targets = torch.from_numpy(y[idx]).float().to(device)

        with torch.autocast(device_type="cuda" if device.type == "cuda" else "cpu"):
            out = model(b_ids, b_mask)
            loss = F.binary_cross_entropy_with_logits(out["logits"].float(), targets, reduction="sum")

        total += loss.item()
        probabilities.append(out["probabilities"].float().cpu().numpy())
    return total / (len(indices) * y.shape[1]), np.concatenate(probabilities)


def freeze_lower_layers(encoder, unfreeze_top: int) -> None:
    """Train only the top `unfreeze_top` transformer layers (-1 = train everything)."""
    if unfreeze_top < 0:
        return
    layers = encoder.encoder.layer
    encoder.embeddings.requires_grad_(False)
    for i, layer in enumerate(layers):
        layer.requires_grad_(i >= len(layers) - unfreeze_top)


def build_optimizer(model, config: FinetuneConfig):
    # Separate encoder and head parameters
    encoder_params = []
    head_params = []
    for name, param in model.named_parameters():
        if not param.requires_grad:
            continue
        if name.startswith("encoder."):
            encoder_params.append((name, param))
        else:
            head_params.append((name, param))

    # Apply weight decay to everything except biases and layernorm/norm weights
    no_decay = ["bias", "LayerNorm.weight", "norm", "A_sym", "A_skew"]

    optimizer_grouped_parameters = [
        {
            "params": [p for n, p in encoder_params if not any(nd in n for nd in no_decay)],
            "weight_decay": config.weight_decay,
            "lr": config.encoder_lr,
        },
        {
            "params": [p for n, p in encoder_params if any(nd in n for nd in no_decay)],
            "weight_decay": 0.0,
            "lr": config.encoder_lr,
        },
        {
            "params": [p for n, p in head_params if not any(nd in n for nd in no_decay)],
            "weight_decay": config.weight_decay,
            "lr": config.head_lr,
        },
        {
            "params": [p for n, p in head_params if any(nd in n for nd in no_decay)],
            "weight_decay": 0.0,
            "lr": config.head_lr,
        },
    ]
    return AdamW(optimizer_grouped_parameters)


def is_update_step(step_idx: int, n_batches: int, accumulation: int) -> bool:
    """Optimizer step after every `accumulation` batches and after the last batch.

    The old test `step_idx + 1 == len(order) // batch_size + 1` missed the
    last batch whenever the training set divided evenly into batches, so the
    final partial accumulation was carried into the next epoch.
    """
    return (step_idx + 1) % accumulation == 0 or step_idx + 1 == n_batches


def get_linear_schedule_with_warmup(optimizer, num_warmup_steps, num_training_steps):
    from torch.optim.lr_scheduler import LambdaLR
    def lr_lambda(current_step: int):
        if current_step < num_warmup_steps:
            return float(current_step) / float(max(1, num_warmup_steps))
        return max(0.0, float(num_training_steps - current_step) / float(max(1, num_training_steps - num_warmup_steps)))
    return LambdaLR(optimizer, lr_lambda)


def fit_e2e(texts, y: np.ndarray, split: dict, config: FinetuneConfig, run_dir: Path,
            n_tactics: int = 14, resume: bool = False, warm_start: bool = False,
            state_dir: Path | None = None):
    run_dir.mkdir(parents=True, exist_ok=True)
    state_dir = state_dir or STATE_ROOT / run_dir.name
    state_dir.mkdir(parents=True, exist_ok=True)
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    best_path, last_path = run_dir / "best.pt", state_dir / "last.pt"

    print(f"Tokenizing {len(texts)} sentences...")
    tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
    encoded = encode(tokenizer, texts)
    input_ids = torch.from_numpy(encoded["input_ids"])
    attention_mask = torch.from_numpy(encoded["attention_mask"])

    print(f"Loading {MODEL_NAME}...")
    encoder = AutoModel.from_pretrained(MODEL_NAME)
    encoder.requires_grad_(True)
    freeze_lower_layers(encoder, config.unfreeze_top)

    torch.manual_seed(config.seed)
    model = TTPExtractorE2E(
        encoder=encoder, n_labels=y.shape[1], d_model=config.d_model,
        d_state=config.d_state, n_layers=config.n_layers, kernel_size=config.kernel_size,
        dropout=config.dropout, classifier=config.classifier
    ).to(device)
    optimizer = build_optimizer(model, config)

    train_idx = split["train"]
    n_batches = math.ceil(len(train_idx) / config.batch_size)
    steps_per_epoch = math.ceil(n_batches / config.gradient_accumulation)
    total_steps = config.max_epochs * steps_per_epoch
    warmup_steps = int(total_steps * config.warmup_ratio)
    scheduler = get_linear_schedule_with_warmup(optimizer, warmup_steps, total_steps)

    pos_weight = compute_pos_weight(y[train_idx]).to(device) if config.use_pos_weight else None
    criterion = FocalBCEWithLogitsLoss(gamma=config.focal_gamma, pos_weight=pos_weight, reduction="mean")
    scaler = torch.amp.GradScaler("cuda") if device.type == "cuda" else None
    shuffler = torch.Generator().manual_seed(config.seed)
    stopper = EarlyStopping(config.patience)
    history = []

    if resume and last_path.exists():
        state = torch.load(last_path, weights_only=False, map_location="cpu")
        model.load_state_dict(state["model"])
        optimizer.load_state_dict(state["optimizer"])
        scheduler.load_state_dict(state["scheduler"])
        if scaler is not None and state.get("scaler"):
            scaler.load_state_dict(state["scaler"])
        vars(stopper).update(state["stopper"])
        history = state["history"]
        shuffler.set_state(state["shuffler"])
        set_rng_state(state, device)
        print(f"resumed after epoch {len(history)}")
    elif warm_start:
        # Old runs saved only best.pt: restart from the best weights with the
        # schedule moved to that epoch. Approximate (AdamW moments start at zero,
        # and random states differ from the original run).
        model.load_state_dict(torch.load(best_path, map_location=device, weights_only=True))
        old = json.loads((run_dir / "history.json").read_text(encoding="utf-8"))
        best = min(old, key=lambda r: r["val_loss"])
        history = [r for r in old if r["epoch"] <= best["epoch"]]
        stopper.best, stopper.best_epoch = best["val_loss"], best["epoch"]
        for _ in range(best["epoch"]):
            torch.randperm(len(train_idx), generator=shuffler)
        for _ in range(best["epoch"] * steps_per_epoch):
            scheduler.step()
        print(f"warm start from best.pt (epoch {best['epoch']}, val loss {best['val_loss']:.4f}); "
              "approximate: optimizer moments reset")

    (run_dir / "config.json").write_text(json.dumps(asdict(config), indent=2), encoding="utf-8")
    trainable = sum(p.numel() for p in model.parameters() if p.requires_grad)
    print(f"Starting training on {device}, {trainable:,} trainable parameters")
    print("note: training loss is focal loss; validation loss is plain BCE "
          "(early stopping uses the BCE number, so the two are not directly comparable)")

    for epoch in range(len(history) + 1, config.max_epochs + 1):
        if stopper.should_stop:
            break
        started = time.time()
        model.train()
        order = train_idx[torch.randperm(len(train_idx), generator=shuffler).numpy()]
        loss_sum = 0.0
        n_samples = 0
        for step_idx, idx in enumerate(batches(order, config.batch_size)):
            b_ids, b_mask = trim(input_ids[idx], attention_mask[idx])
            b_ids, b_mask = b_ids.to(device), b_mask.to(device)
            targets = torch.from_numpy(y[idx]).float().to(device)

            with torch.autocast(device_type="cuda" if device.type == "cuda" else "cpu"):
                out = model(b_ids, b_mask)
                loss = criterion(out["logits"].float(), targets) / config.gradient_accumulation

            if scaler:
                scaler.scale(loss).backward()
            else:
                loss.backward()
            loss_sum += loss.item() * config.gradient_accumulation * len(idx)
            n_samples += len(idx)

            if is_update_step(step_idx, n_batches, config.gradient_accumulation):
                if scaler:
                    scaler.step(optimizer)
                    scaler.update()
                else:
                    optimizer.step()
                optimizer.zero_grad()
                scheduler.step()

        val_loss, val_prob = evaluate_e2e(model, input_ids, attention_mask, y, split["val"],
                                          config.batch_size * 2, device)
        val_y = y[split["val"]]
        tac, tech = slice(0, n_tactics), slice(n_tactics, y.shape[1])
        record = {
            "epoch": epoch,
            "train_loss": loss_sum / n_samples,
            "val_loss": val_loss,
            "val_f1_tactics": micro_f1(val_prob[:, tac], val_y[:, tac]),
            "val_f1_techniques": micro_f1(val_prob[:, tech], val_y[:, tech]),
            "val_macro_f1_tactics": macro_f1_supported(val_prob[:, tac], val_y[:, tac]),
            "val_macro_f1_techniques": macro_f1_supported(val_prob[:, tech], val_y[:, tech]),
            "seconds": time.time() - started,
        }
        history.append(record)
        improved = stopper.update(val_loss, epoch)
        if improved:
            torch.save(model.state_dict(), best_path)
        torch.save({
            "model": model.state_dict(), "optimizer": optimizer.state_dict(),
            "scheduler": scheduler.state_dict(),
            "scaler": None if scaler is None else scaler.state_dict(),
            "stopper": dict(vars(stopper)), "history": history,
            "shuffler": shuffler.get_state(), **rng_state(device),
        }, last_path)
        (run_dir / "history.json").write_text(json.dumps(history, indent=2), encoding="utf-8")
        write_summary(run_dir, history, stopper, finished=False)
        print(f"epoch {epoch:3d}  train {record['train_loss']:.4f}  val {val_loss:.4f}"
              f"{' *' if improved else '  '}  F1 tac {record['val_f1_tactics']:.3f}"
              f"  tech {record['val_f1_techniques']:.3f}"
              f"  macro tech {record['val_macro_f1_techniques']:.3f}  {record['seconds']:.0f}s",
              flush=True)

    print(str(write_summary(run_dir, history, stopper, finished=True)))


def write_summary(run_dir: Path, history: list, stopper: EarlyStopping, finished: bool) -> dict:
    if not finished:
        reason = "in_progress"
    else:
        reason = "early_stopping" if stopper.should_stop else "max_epochs"
    summary = {
        "epochs_run": len(history), "best_epoch": stopper.best_epoch,
        "best_val_loss": stopper.best, "stop_reason": reason, "finetuned": True,
    }
    (run_dir / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return summary


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--csv", type=Path, required=True)
    p.add_argument("--splits", type=Path, default=Path("artifacts/splits"))
    p.add_argument("--runs", type=Path, default=Path("runs"))
    p.add_argument("--seed", type=int, default=0, help="model seed (and split seed by default)")
    p.add_argument("--split-seed", type=int, default=None,
                   help="train on a different split than --seed (for seed ensembles)")
    p.add_argument("--run-name", default=None)
    p.add_argument("--max-epochs", type=int, default=None)
    p.add_argument("--unfreeze-top", type=int, default=None)
    p.add_argument("--resume", action="store_true")
    p.add_argument("--warm-start-from-best", action="store_true")
    p.add_argument("--state-dir", type=Path, default=None)
    args = p.parse_args()

    texts, y, vocab = load_dataset(args.csv)
    split_seed = args.seed if args.split_seed is None else args.split_seed
    split = load_split(args.splits / f"seed_{split_seed}.json")
    run_dir = args.runs / (args.run_name or f"finetune_seed_{args.seed}")
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "split.json").write_text(json.dumps({"split_seed": split_seed}), encoding="utf-8")
    config = FinetuneConfig(seed=args.seed)
    if (args.resume or args.warm_start_from_best) and (run_dir / "config.json").exists():
        config = FinetuneConfig(**json.loads((run_dir / "config.json").read_text(encoding="utf-8")))
    if args.max_epochs is not None:
        config.max_epochs = args.max_epochs
    if args.unfreeze_top is not None:
        config.unfreeze_top = args.unfreeze_top
    fit_e2e(texts, y, split, config, run_dir, n_tactics=len(vocab.tactics), resume=args.resume,
            warm_start=args.warm_start_from_best, state_dir=args.state_dir)


if __name__ == "__main__":
    main()
