"""Module 7: training loop for the TTP extraction model.

Table V: Adam, lr 1e-4, dropout 0.1, up to 100 epochs, 10% validation split.
Early stopping: stop after `patience` epochs without a new best validation
loss, then restore the best weights.

Presets:
  paper  Table V exactly (the default). Every option added later is off.
  tuned  configs/tuned.json, written by the hyperparameter search.

Options beyond the paper (Phase 3 and 4 of the plan) are TrainConfig fields
whose defaults reproduce the paper; each has a CLI flag of the same name,
e.g. --loss asl, --weight-decay 1e-3, --covariance diagonal.
"""
from __future__ import annotations

import argparse
import copy
import json
import math
import time
from dataclasses import asdict, dataclass, fields, replace
from pathlib import Path

import numpy as np
import torch
import torch.nn.functional as F

from ttp_extraction.classifier.model import CLASSIFIERS, TTPExtractor
from ttp_extraction.data.batching import DeviceSequences, pad_batch
from ttp_extraction.training.losses import build_loss, positive_weights

TUNED_CONFIG = Path("configs/tuned.json")

CHOICES = {
    "classifier": CLASSIFIERS,
    "loss": ("bce", "weighted_bce", "focal", "asl"),
    "pos_weight": ("none", "sqrt", "log"),
    "optimizer": ("adam", "adamw"),
    "lr_schedule": ("none", "cosine", "plateau"),
    "early_stop_metric": ("val_loss", "val_macro_f1", "val_micro_f1"),
    "sampler": ("random", "rare_oversample"),
    "activation": ("sigmoid", "silu"),
    "block": ("paper", "mamba"),
    "covariance": ("full", "diagonal"),
    "repr_norm": ("none", "sum_s"),
    "features": ("last", "last4_mean", "last4_concat"),
}


@dataclass
class TrainConfig:
    seed: int = 0
    d_input: int = 768
    d_model: int = 48               # Table V: SSM Dim
    d_state: int = 4                # Table V: SSM Head (read as state size N)
    n_layers: int = 3               # Table V: SSM Layer
    kernel_size: int = 4            # implementation decision (Mamba default)
    dropout: float = 0.1            # Table V
    classifier: str = "concat"      # Eq. 5 reading, see classifier/model.py
    lr: float = 1e-4                # Table V
    batch_size: int = 32            # implementation decision (paper silent)
    max_epochs: int = 100           # Table V
    patience: int = 5               # paper: five-iteration early stopping
    # --- Phase 3: loss / imbalance (defaults = paper) ---
    loss: str = "bce"
    focal_gamma: float = 2.0
    asl_gamma_neg: float = 4.0
    asl_gamma_pos: float = 0.0
    asl_clip: float = 0.05
    pos_weight: str = "none"
    pos_weight_cap: float = 10.0
    prior_bias_init: bool = False
    # --- Phase 3: regularisation / optimisation ---
    optimizer: str = "adam"
    weight_decay: float = 0.0
    input_dropout: float = 0.0
    token_dropout: float = 0.0
    grad_clip: float = 0.0          # 0 = off
    lr_schedule: str = "none"
    warmup_epochs: int = 0
    early_stop_metric: str = "val_loss"
    ema: float = 0.0                # 0 = off, e.g. 0.999
    sampler: str = "random"
    rare_threshold: int = 20        # rare_oversample: techniques with < this many train rows
    oversample_max: int = 3         # rare_oversample: at most this many copies of a row
    # --- Phase 4: model capacity / variants ---
    activation: str = "sigmoid"
    block: str = "paper"
    covariance: str = "full"
    bidirectional: bool = False
    repr_norm: str = "none"
    similarity_temperature: bool = False
    features: str = "last"          # SecureBERT layers in the embedding cache (paper: last)

    def __post_init__(self):
        for name, allowed in CHOICES.items():
            if getattr(self, name) not in allowed:
                raise ValueError(f"{name} must be one of {allowed}, got {getattr(self, name)!r}")

    @classmethod
    def from_dict(cls, values: dict) -> "TrainConfig":
        """Load a saved config.json, including old ones with `per_label_classifier`."""
        values = dict(values)
        if "per_label_classifier" in values:
            old = values.pop("per_label_classifier")
            values.setdefault("classifier", "per_label" if old else "shared")
        known = {f.name for f in fields(cls)}
        unknown = set(values) - known
        if unknown:
            raise ValueError(f"unknown config fields: {sorted(unknown)}")
        return cls(**values)


PRESETS = ("paper", "tuned")


def preset_config(name: str, tuned_path: Path = TUNED_CONFIG) -> TrainConfig:
    if name == "paper":
        return TrainConfig()
    if name == "tuned":
        if not tuned_path.exists():
            raise SystemExit(f"--preset tuned needs {tuned_path}; run the search first")
        return TrainConfig.from_dict(json.loads(tuned_path.read_text(encoding="utf-8")))
    raise ValueError(f"preset must be one of {PRESETS}, got {name!r}")


def changed_fields(config: TrainConfig) -> dict:
    """Fields that differ from the paper preset (seed and max_epochs ignored)."""
    paper = asdict(TrainConfig())
    return {k: v for k, v in asdict(config).items()
            if k not in ("seed", "max_epochs") and paper[k] != v}


class EarlyStopping:
    def __init__(self, patience: int):
        self.patience, self.best, self.best_epoch, self.wait = patience, math.inf, 0, 0

    def update(self, value: float, epoch: int) -> bool:
        """Record a validation score (lower is better); return True if it is a new best."""
        if value < self.best:
            self.best, self.best_epoch, self.wait = value, epoch, 0
            return True
        self.wait += 1
        return False

    @property
    def should_stop(self) -> bool:
        return self.wait >= self.patience


def batches(indices: np.ndarray, batch_size: int):
    for start in range(0, len(indices), batch_size):
        yield indices[start : start + batch_size]


def load_batch(sequences, y: np.ndarray, idx: np.ndarray, device: torch.device):
    if isinstance(sequences, DeviceSequences):
        embeddings, mask = sequences.batch(idx)
    else:
        embeddings, mask = pad_batch([sequences[int(i)] for i in idx])
    targets = torch.from_numpy(y[idx]).float()
    return embeddings.to(device), mask.to(device), targets.to(device)


def micro_f1(probabilities: np.ndarray, y: np.ndarray, threshold: float = 0.5) -> float:
    predicted, actual = probabilities > threshold, y == 1
    true_positive = (predicted & actual).sum()
    return float(2 * true_positive / max(predicted.sum() + actual.sum(), 1))


def macro_f1_supported(probabilities: np.ndarray, y: np.ndarray, threshold: float = 0.5) -> float:
    """Mean per-label F1 over labels with at least one positive row."""
    predicted, actual = probabilities > threshold, y == 1
    tp = (predicted & actual).sum(axis=0)
    denominator = predicted.sum(axis=0) + actual.sum(axis=0)
    supported = actual.sum(axis=0) > 0
    return float((2 * tp[supported] / denominator[supported]).mean()) if supported.any() else 0.0


@torch.no_grad()
def evaluate(model, sequences, y, indices, batch_size: int, device) -> tuple[float, np.ndarray]:
    """Return (mean BCE loss, probabilities of shape (len(indices), L)), dropout off."""
    model.eval()
    total, probabilities = 0.0, []
    for idx in batches(indices, batch_size):
        embeddings, mask, targets = load_batch(sequences, y, idx, device)
        out = model(embeddings, mask)
        total += F.binary_cross_entropy_with_logits(out["logits"], targets, reduction="sum").item()
        probabilities.append(out["probabilities"].cpu().numpy())
    return total / (len(indices) * y.shape[1]), np.concatenate(probabilities)


def build_model(config: TrainConfig, n_labels: int) -> TTPExtractor:
    return TTPExtractor(
        n_labels=n_labels, d_input=config.d_input, d_model=config.d_model,
        d_state=config.d_state, n_layers=config.n_layers, kernel_size=config.kernel_size,
        dropout=config.dropout, classifier=config.classifier,
        activation=config.activation, block=config.block, bidirectional=config.bidirectional,
        input_dropout=config.input_dropout, covariance=config.covariance,
        similarity_temperature=config.similarity_temperature, repr_norm=config.repr_norm,
    )


def build_optimizer(model, config: TrainConfig):
    if config.optimizer == "adamw":
        return torch.optim.AdamW(model.parameters(), lr=config.lr, weight_decay=config.weight_decay)
    return torch.optim.Adam(model.parameters(), lr=config.lr, weight_decay=config.weight_decay)


def build_scheduler(optimizer, config: TrainConfig):
    """Stepped once per epoch. 'plateau' halves the lr after 2 epochs without improvement."""
    if config.lr_schedule == "plateau":
        return torch.optim.lr_scheduler.ReduceLROnPlateau(optimizer, factor=0.5, patience=2)
    if config.lr_schedule == "cosine":
        warmup, total = config.warmup_epochs, max(config.max_epochs, 1)

        def factor(epoch: int) -> float:   # epoch counts completed epochs
            if epoch < warmup:
                return (epoch + 1) / warmup
            return 0.5 * (1 + math.cos(math.pi * (epoch - warmup) / max(total - warmup, 1)))

        return torch.optim.lr_scheduler.LambdaLR(optimizer, factor)
    if config.warmup_epochs > 0:
        return torch.optim.lr_scheduler.LambdaLR(
            optimizer, lambda e: min(1.0, (e + 1) / config.warmup_epochs))
    return None


def row_repeats(y_train: np.ndarray, n_tactics: int, config: TrainConfig) -> np.ndarray:
    """How many copies of each training row one epoch sees (1 = no oversampling).

    rare_oversample: a row containing a technique with fewer than
    `rare_threshold` training rows is repeated ceil(rare_threshold / count)
    times for its rarest technique, capped at `oversample_max`.
    """
    repeats = np.ones(len(y_train), dtype=np.int64)
    if config.sampler == "random":
        return repeats
    techniques = y_train[:, n_tactics:].astype(bool)
    counts = techniques.sum(axis=0)
    for row in np.flatnonzero(techniques.any(axis=1)):
        rarest = counts[techniques[row]].min()
        if rarest < config.rare_threshold:
            repeats[row] = min(config.oversample_max, math.ceil(config.rare_threshold / rarest))
    return repeats


def drop_tokens(embeddings, mask, rate: float):
    """Training-only augmentation: hide a random `rate` of real tokens (never the first)."""
    drop = (torch.rand(mask.shape, device=mask.device) < rate) & mask
    drop[:, 0] = False
    keep = mask & ~drop
    return embeddings * keep.unsqueeze(-1).to(embeddings.dtype), keep


class EMA:
    """Exponential moving average of the weights, used for validation and best.pt."""

    def __init__(self, model, decay: float):
        self.decay = decay
        self.shadow = {k: v.detach().clone() for k, v in model.state_dict().items()}

    @torch.no_grad()
    def update(self, model) -> None:
        for k, v in model.state_dict().items():
            if v.dtype.is_floating_point:
                self.shadow[k].mul_(self.decay).add_(v, alpha=1 - self.decay)
            else:
                self.shadow[k].copy_(v)


def rng_state(device: torch.device) -> dict:
    """Every random state training draws from (dropout on the GPU uses the CUDA one)."""
    state = {"torch_rng": torch.get_rng_state()}
    if device.type == "cuda":
        state["cuda_rng"] = torch.cuda.get_rng_state(device)
    return state


def set_rng_state(state: dict, device: torch.device) -> None:
    torch.set_rng_state(state["torch_rng"])
    if device.type == "cuda" and "cuda_rng" in state:
        torch.cuda.set_rng_state(state["cuda_rng"], device)


def fit(sequences, y: np.ndarray, split: dict, config: TrainConfig, run_dir: Path,
        n_tactics: int = 14, resume: bool = False, device=None, log=print, on_epoch=None):
    """Train with early stopping and return (model with the best weights, history).

    on_epoch(record) is called after every epoch (the hyperparameter search
    uses it to stop hopeless trials early).
    """
    run_dir.mkdir(parents=True, exist_ok=True)
    device = device or torch.device("cuda" if torch.cuda.is_available() else "cpu")
    best_path, last_path = run_dir / "best.pt", run_dir / "last.pt"
    if device.type == "cuda" and not isinstance(sequences, DeviceSequences):
        sequences = DeviceSequences(sequences, device)
    train_idx, n_labels = split["train"], y.shape[1]
    y_train = y[train_idx]

    torch.manual_seed(config.seed)
    model = build_model(config, n_labels).to(device)
    if config.prior_bias_init:
        model.init_prior_bias(torch.from_numpy(y_train.mean(axis=0)).float())
    pos_weight = positive_weights(y_train, config.pos_weight, config.pos_weight_cap)
    criterion = build_loss(config.loss, None if pos_weight is None else pos_weight.to(device),
                           config.focal_gamma, config.asl_gamma_neg, config.asl_gamma_pos,
                           config.asl_clip).to(device)
    optimizer = build_optimizer(model, config)
    scheduler = build_scheduler(optimizer, config)
    ema = EMA(model, config.ema) if config.ema > 0 else None
    repeats = row_repeats(y_train, n_tactics, config)
    shuffler = torch.Generator().manual_seed(config.seed)
    stopper = EarlyStopping(config.patience)
    history: list[dict] = []

    if resume and last_path.exists():
        state = torch.load(last_path, weights_only=False, map_location="cpu")
        model.load_state_dict(state["model"])
        optimizer.load_state_dict(state["optimizer"])
        if scheduler is not None and state.get("scheduler") is not None:
            scheduler.load_state_dict(state["scheduler"])
        if ema is not None and state.get("ema") is not None:
            ema.shadow = {k: v.to(device) for k, v in state["ema"].items()}
        vars(stopper).update(state["stopper"])
        history = state["history"]
        shuffler.set_state(state["shuffler"])
        set_rng_state(state, device)
        log(f"resumed after epoch {len(history)}")
    (run_dir / "config.json").write_text(json.dumps(asdict(config), indent=2), encoding="utf-8")
    if repeats.max() > 1:
        log(f"rare_oversample: {int((repeats > 1).sum())} rows repeated, "
            f"epoch size {int(repeats.sum())} instead of {len(train_idx)}")

    expanded = np.repeat(train_idx, repeats)
    for epoch in range(len(history) + 1, config.max_epochs + 1):
        if stopper.should_stop:
            break
        started = time.time()
        model.train()
        order = expanded[torch.randperm(len(expanded), generator=shuffler).numpy()]
        loss_sum = score_sum = hidden_sum = 0.0
        n_batches = 0
        for idx in batches(order, config.batch_size):
            embeddings, mask, targets = load_batch(sequences, y, idx, device)
            if config.token_dropout > 0:
                embeddings, mask = drop_tokens(embeddings, mask, config.token_dropout)
            out = model(embeddings, mask)
            loss = criterion(out["logits"], targets)
            optimizer.zero_grad()
            loss.backward()
            if config.grad_clip > 0:
                torch.nn.utils.clip_grad_norm_(model.parameters(), config.grad_clip)
            optimizer.step()
            if ema is not None:
                ema.update(model)
            loss_sum += loss.item() * len(idx)
            score_sum += out["similarity"].sum().item() / (mask.sum().item() * n_labels)
            hidden_sum += out["hidden"][mask].std().item()
            n_batches += 1

        if ema is not None:
            live = copy.deepcopy(model.state_dict())
            model.load_state_dict(ema.shadow)
        val_loss, val_prob = evaluate(model, sequences, y, split["val"], config.batch_size, device)
        val_y = y[split["val"]]
        tac, tech = slice(0, n_tactics), slice(n_tactics, n_labels)
        record = {
            "epoch": epoch,
            "train_loss": loss_sum / len(order),
            "val_loss": val_loss,
            "val_f1_tactics": micro_f1(val_prob[:, tac], val_y[:, tac]),
            "val_f1_techniques": micro_f1(val_prob[:, tech], val_y[:, tech]),
            "val_macro_f1_tactics": macro_f1_supported(val_prob[:, tac], val_y[:, tac]),
            "val_macro_f1_techniques": macro_f1_supported(val_prob[:, tech], val_y[:, tech]),
            "s_mean": score_sum / n_batches,
            "h_std": hidden_sum / n_batches,
            "lr": optimizer.param_groups[0]["lr"],
            "seconds": time.time() - started,
        }
        history.append(record)
        if config.early_stop_metric == "val_loss":
            score = val_loss
        elif config.early_stop_metric == "val_macro_f1":
            score = -(record["val_macro_f1_tactics"] + record["val_macro_f1_techniques"]) / 2
        else:
            score = -(record["val_f1_tactics"] + record["val_f1_techniques"]) / 2
        improved = stopper.update(score, epoch)
        if improved:
            torch.save(model.state_dict(), best_path)
        if ema is not None:
            model.load_state_dict(live)
        if isinstance(scheduler, torch.optim.lr_scheduler.ReduceLROnPlateau):
            scheduler.step(score)
        elif scheduler is not None:
            scheduler.step()
        torch.save({
            "model": model.state_dict(), "optimizer": optimizer.state_dict(),
            "scheduler": None if scheduler is None else scheduler.state_dict(),
            "ema": None if ema is None else ema.shadow,
            "stopper": dict(vars(stopper)), "history": history,
            "shuffler": shuffler.get_state(), **rng_state(device),
        }, last_path)
        (run_dir / "history.json").write_text(json.dumps(history, indent=2), encoding="utf-8")
        log(f"epoch {epoch:3d}  train {record['train_loss']:.4f}  val {val_loss:.4f}"
            f"{' *' if improved else '  '}  F1 tac {record['val_f1_tactics']:.3f}"
            f"  tech {record['val_f1_techniques']:.3f}  macro tech {record['val_macro_f1_techniques']:.3f}"
            f"  S {record['s_mean']:.3f}  H {record['h_std']:.2f}  {record['seconds']:.0f}s")
        if on_epoch is not None:
            on_epoch(record)

    model.load_state_dict(torch.load(best_path, map_location=device))
    best = history[stopper.best_epoch - 1]
    summary = {
        "epochs_run": len(history), "best_epoch": stopper.best_epoch,
        "best_val_loss": best["val_loss"],
        "early_stop_metric": config.early_stop_metric, "best_score": stopper.best,
        "stop_reason": "early_stopping" if stopper.should_stop else "max_epochs",
        "wall_seconds": sum(r["seconds"] for r in history),
    }
    (run_dir / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    log(str(summary))
    return model, history


def _str2bool(text: str) -> bool:
    if text.lower() in ("1", "true", "yes", "on"):
        return True
    if text.lower() in ("0", "false", "no", "off"):
        return False
    raise argparse.ArgumentTypeError(f"expected true/false, got {text!r}")


def add_config_arguments(p: argparse.ArgumentParser) -> None:
    """One CLI flag per TrainConfig field; unset flags keep the preset's value."""
    p.add_argument("--preset", choices=PRESETS, default="paper")
    p.add_argument("--per-label", action="store_true",
                   help="deprecated: same as --classifier per_label")
    for f in fields(TrainConfig):
        if f.name == "seed":
            continue
        kind = _str2bool if isinstance(f.default, bool) else type(f.default)
        p.add_argument("--" + f.name.replace("_", "-"), type=kind, default=None,
                       choices=CHOICES.get(f.name))


def config_from_args(args) -> TrainConfig:
    config = preset_config(args.preset)
    changes = {f.name: getattr(args, f.name) for f in fields(TrainConfig)
               if f.name != "seed" and getattr(args, f.name, None) is not None}
    if args.per_label:
        changes.setdefault("classifier", "per_label")
    return replace(config, seed=args.seed, **changes)


def main() -> None:
    from ttp_extraction.data.labels import load_dataset
    from ttp_extraction.data.splits import load_split
    from ttp_extraction.securebert.cache import EmbeddingCache, cache_root
    from ttp_extraction.training.experiments import log_run

    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--csv", type=Path, required=True)
    p.add_argument("--cache", type=Path, default=None, help="default: chosen by --features")
    p.add_argument("--splits", type=Path, default=Path("artifacts/splits"))
    p.add_argument("--runs", type=Path, default=Path("runs"))
    p.add_argument("--seed", type=int, default=0, help="model seed (and split seed by default)")
    p.add_argument("--split-seed", type=int, default=None,
                   help="train on a different split than --seed (for seed ensembles)")
    p.add_argument("--run-name", default=None, help="default: <preset>_seed_<seed>")
    p.add_argument("--changed", default=None,
                   help="what this run changes, for experiments.csv (default: the changed fields)")
    p.add_argument("--resume", action="store_true")
    add_config_arguments(p)
    args = p.parse_args()

    _, y, vocab = load_dataset(args.csv)
    config = config_from_args(args)
    cache = EmbeddingCache(args.cache or cache_root(config.features))
    assert len(cache) == len(y), "embedding cache and dataset have different lengths"
    if cache.meta.get("layers", "last") != config.features:
        raise SystemExit(f"cache holds {cache.meta.get('layers', 'last')!r} features, "
                         f"config wants {config.features!r}")
    if config.d_input != cache.meta["hidden_size"]:
        config = replace(config, d_input=int(cache.meta["hidden_size"]))
    split_seed = args.seed if args.split_seed is None else args.split_seed
    split = load_split(args.splits / f"seed_{split_seed}.json")
    run_name = args.run_name or f"{args.preset}_seed_{args.seed}"
    changed = args.changed if args.changed is not None else json.dumps(changed_fields(config))
    (args.runs / run_name).mkdir(parents=True, exist_ok=True)
    (args.runs / run_name / "split.json").write_text(
        json.dumps({"split_seed": split_seed}), encoding="utf-8")
    model, history = fit(cache, y, split, config, args.runs / run_name,
                         n_tactics=len(vocab.tactics), resume=args.resume)
    log_run(run_name, args.preset, changed, config, args.runs / run_name,
            model, cache, y, split, len(vocab.tactics))


if __name__ == "__main__":
    main()
