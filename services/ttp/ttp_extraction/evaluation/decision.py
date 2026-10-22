"""Decision layer: turn label probabilities into label sets (Phase 2).

Everything here is FITTED ON VALIDATION ONLY and then applied unchanged to
any other split. Three independent steps, applied in this order:

1. thresholds  fixed      0.5 for every label (the paper)
               global     one threshold for all 203 labels, best val micro-F1
               per_slice  one threshold for tactics, one for techniques
               per_label  one threshold per label (labels with >= min_pos
                          positive val rows), others fall back to per_slice
2. hierarchy   a predicted technique also switches on its tactic(s); the
               technique -> tactic map is built from TRAINING rows only
3. top-1       a sentence with no tactic (or no technique) above threshold
               gets its single most probable tactic (or technique); every
               sentence in the dataset has at least one of each
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path

import numpy as np

THRESHOLD_MODES = ("fixed", "global", "per_slice", "per_label")
GRID = np.round(np.arange(0.05, 0.6 + 1e-9, 0.025), 4)          # global / per_slice sweep
LABEL_GRID = np.round(np.arange(0.05, 0.9 + 1e-9, 0.025), 4)    # per-label sweep (clipped range)


def f1_counts(y: np.ndarray, pred: np.ndarray) -> float:
    tp = int((pred & (y == 1)).sum())
    return 2 * tp / max(int(pred.sum()) + int((y == 1).sum()), 1)


def best_threshold(y: np.ndarray, prob: np.ndarray, grid=GRID) -> float:
    """Threshold from `grid` with the highest micro-F1; ties go to the value nearest 0.5."""
    scores = [(f1_counts(y, prob > t), -abs(t - 0.5), t) for t in grid]
    return float(max(scores)[2])


def label_threshold(y: np.ndarray, prob: np.ndarray, grid=LABEL_GRID) -> float:
    """Per-label F1 sweep for one column."""
    return best_threshold(y[:, None], prob[:, None], grid)


def fit_thresholds(y_val: np.ndarray, prob_val: np.ndarray, n_tactics: int,
                   mode: str = "fixed", min_pos: int = 5) -> np.ndarray:
    """Return one threshold per label, shape (L,), fitted on validation rows."""
    if mode not in THRESHOLD_MODES:
        raise ValueError(f"threshold mode must be one of {THRESHOLD_MODES}, got {mode!r}")
    n_labels = y_val.shape[1]
    if mode == "fixed":
        return np.full(n_labels, 0.5)
    if mode == "global":
        return np.full(n_labels, best_threshold(y_val, prob_val))
    slices = (slice(0, n_tactics), slice(n_tactics, n_labels))
    thresholds = np.empty(n_labels)
    for s in slices:
        thresholds[s] = best_threshold(y_val[:, s], prob_val[:, s])
    if mode == "per_label":
        for label in np.flatnonzero(y_val.sum(axis=0) >= min_pos):
            thresholds[label] = label_threshold(y_val[:, label], prob_val[:, label])
    return thresholds


def technique_to_tactics(y_train: np.ndarray, n_tactics: int, min_share: float = 0.5
                         ) -> dict[int, list[int]]:
    """Technique column -> tactic columns, from training rows only.

    Technique T maps to tactic A when A is flagged on at least `min_share` of
    the training rows that flag T. Keys and values are column indices in the
    203-label matrix.
    """
    tactics, techniques = y_train[:, :n_tactics], y_train[:, n_tactics:]
    mapping = {}
    for j in range(techniques.shape[1]):
        rows = techniques[:, j] == 1
        if rows.sum() == 0:
            continue
        share = tactics[rows].mean(axis=0)
        linked = [int(a) for a in np.flatnonzero(share >= min_share)]
        if linked:
            mapping[n_tactics + j] = linked
    return mapping


def apply_hierarchy(pred: np.ndarray, mapping: dict[int, list[int]]) -> np.ndarray:
    """A predicted technique switches on its tactic(s). Only ever adds labels."""
    out = pred.copy()
    for technique, tactics in mapping.items():
        rows = pred[:, technique]
        for tactic in tactics:
            out[:, tactic] |= rows
    return out


def apply_top1(pred: np.ndarray, prob: np.ndarray, n_tactics: int) -> np.ndarray:
    """Rows with no tactic (technique) get their most probable tactic (technique)."""
    out = pred.copy()
    for s in (slice(0, n_tactics), slice(n_tactics, pred.shape[1])):
        empty = ~out[:, s].any(axis=1)
        best = prob[:, s].argmax(axis=1) + s.start
        out[np.flatnonzero(empty), best[empty]] = True
    return out


@dataclass
class DecisionLayer:
    threshold_mode: str = "fixed"
    hierarchy: bool = False
    top1: bool = False
    min_pos: int = 5
    hierarchy_min_share: float = 0.5
    thresholds: list = field(default_factory=list)
    hierarchy_map: dict = field(default_factory=dict)

    def fit(self, y_val, prob_val, n_tactics: int, y_train=None) -> "DecisionLayer":
        self.n_tactics = n_tactics
        self.thresholds = fit_thresholds(y_val, prob_val, n_tactics, self.threshold_mode,
                                         self.min_pos).tolist()
        if self.hierarchy:
            if y_train is None:
                raise ValueError("the hierarchy map needs the training labels")
            self.hierarchy_map = technique_to_tactics(y_train, n_tactics, self.hierarchy_min_share)
        return self

    def predict(self, prob: np.ndarray) -> np.ndarray:
        pred = prob > np.asarray(self.thresholds)[None, :]
        if self.hierarchy:
            pred = apply_hierarchy(pred, {int(k): v for k, v in self.hierarchy_map.items()})
        if self.top1:
            pred = apply_top1(pred, prob, self.n_tactics)
        return pred

    @property
    def name(self) -> str:
        return (f"{self.threshold_mode}" + ("+hier" if self.hierarchy else "")
                + ("+top1" if self.top1 else ""))

    def save(self, path: Path, labels=None) -> None:
        payload = {**asdict(self), "n_tactics": self.n_tactics, "labels": list(labels or [])}
        payload["hierarchy_map"] = {str(k): v for k, v in self.hierarchy_map.items()}
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    @classmethod
    def load(cls, path: Path) -> "DecisionLayer":
        payload = json.loads(path.read_text(encoding="utf-8"))
        n_tactics = payload.pop("n_tactics")
        payload.pop("labels", None)
        layer = cls(**payload)
        layer.n_tactics = n_tactics
        return layer


def cross_fitted_predictions(layer_args: dict, y_val, prob_val, n_tactics: int, y_train=None,
                             folds: int = 5, seed: int = 0) -> np.ndarray:
    """Honest validation estimate: fit on (folds-1)/folds of val, predict the rest."""
    order = np.random.default_rng(seed).permutation(len(y_val))
    pred = np.zeros(prob_val.shape, dtype=bool)
    for part in np.array_split(order, folds):
        fit_rows = np.setdiff1d(order, part)
        layer = DecisionLayer(**layer_args).fit(y_val[fit_rows], prob_val[fit_rows],
                                                n_tactics, y_train)
        pred[part] = layer.predict(prob_val[part])
    return pred
