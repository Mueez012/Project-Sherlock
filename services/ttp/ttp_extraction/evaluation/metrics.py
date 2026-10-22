"""Module 8: precision / recall / F1 for tactics and techniques (Table VI).

Averages reported for each slice (tactics, techniques):
  micro                   pool every (sentence, label) decision; Table VI style
  macro                   mean of per-label F1 over ALL labels in the slice;
                          labels with no rows in the split count as F1 = 0
  macro_supported_labels  mean over labels that have at least one row in the
                          split. This is the main macro number: about 50
                          techniques have no test rows in a given split, and
                          counting them as 0 says nothing about the model
  weighted                per-label F1 weighted by support
  samples                 F1 per sentence, then averaged
"""
from __future__ import annotations

import numpy as np
from sklearn.metrics import precision_recall_fscore_support

AVERAGES = ("micro", "macro", "weighted", "samples")
BUCKETS = (("100+", 100, None), ("10-99", 10, 100), ("<10", 0, 10))   # train rows

# Table VI, ThreatMAMBA row (percent).
PAPER = {
    "tactics": {"precision": 89.75, "recall": 86.83, "f1": 88.26},
    "techniques": {"precision": 84.60, "recall": 79.28, "f1": 81.85},
}


def prf(y_true: np.ndarray, y_pred: np.ndarray, average: str, labels=None) -> dict:
    p, r, f, _ = precision_recall_fscore_support(
        y_true, y_pred, average=average, labels=labels, zero_division=0
    )
    return {"precision": 100 * float(p), "recall": 100 * float(r), "f1": 100 * float(f)}


def slice_report_from_predictions(y_true: np.ndarray, y_pred: np.ndarray) -> dict:
    y_pred = np.asarray(y_pred).astype(np.int8)
    supported = np.flatnonzero(y_true.sum(axis=0) > 0)
    averages = AVERAGES if y_true.shape[1] >= 2 else tuple(a for a in AVERAGES if a != "samples")
    report = {average: prf(y_true, y_pred, average) for average in averages}
    report["macro_supported_labels"] = prf(y_true, y_pred, "macro", labels=supported)
    report["labels"] = int(y_true.shape[1])
    report["labels_with_support"] = int(len(supported))
    report["labels_ever_predicted"] = int((y_pred.sum(axis=0) > 0).sum())
    return report


def slice_report(y_true: np.ndarray, probabilities: np.ndarray, threshold: float = 0.5) -> dict:
    return slice_report_from_predictions(y_true, probabilities > threshold)


def evaluate_label_sets(y_true: np.ndarray, y_pred: np.ndarray, n_tactics: int) -> dict:
    return {
        "tactics": slice_report_from_predictions(y_true[:, :n_tactics], y_pred[:, :n_tactics]),
        "techniques": slice_report_from_predictions(y_true[:, n_tactics:], y_pred[:, n_tactics:]),
    }


def evaluate_predictions(y_true: np.ndarray, probabilities: np.ndarray,
                         n_tactics: int, threshold: float = 0.5) -> dict:
    return evaluate_label_sets(y_true, probabilities > threshold, n_tactics)


def per_label_rows(y_true: np.ndarray, y_pred: np.ndarray, labels, n_tactics: int,
                   supports: dict[str, np.ndarray], thresholds=None, names=None) -> list[dict]:
    """One row per label: supports per split, P/R/F1 on the evaluated rows, threshold.

    Sorted by training support (rarest first) so rare-label failures are visible.
    P/R/F1 are None when the label has no rows and no predictions (undefined).
    """
    y_pred = np.asarray(y_pred).astype(bool)
    actual = y_true == 1
    rows = []
    for j, label in enumerate(labels):
        tp = int((y_pred[:, j] & actual[:, j]).sum())
        n_pred, n_true = int(y_pred[:, j].sum()), int(actual[:, j].sum())
        p = tp / n_pred if n_pred else None
        r = tp / n_true if n_true else None
        f = 2 * tp / (n_pred + n_true) if n_pred + n_true else None
        rows.append({
            "label": label, "name": (names or {}).get(label, ""),
            "kind": "tactic" if j < n_tactics else "technique",
            **{f"{split}_support": int(s[j]) for split, s in supports.items()},
            "eval_support": n_true, "predicted": n_pred, "true_positives": tp,
            "precision": p, "recall": r, "f1": f,
            "threshold": None if thresholds is None else float(thresholds[j]),
        })
    rows.sort(key=lambda row: (row["kind"] != "tactic", row["train_support"], row["label"]))
    return rows


def support_buckets(rows: list[dict], kind: str = "technique") -> dict:
    """Macro-F1 of labels grouped by training support (labels with eval rows only)."""
    out = {}
    for name, low, high in BUCKETS:
        chosen = [r for r in rows if r["kind"] == kind and r["eval_support"] > 0
                  and r["train_support"] >= low and (high is None or r["train_support"] < high)]
        f1s = [r["f1"] or 0.0 for r in chosen]
        out[name] = {"labels": len(chosen), "macro_f1": 100 * float(np.mean(f1s)) if f1s else None}
    return out


def quality_summary(rows: list[dict]) -> dict:
    """How many labels are good, middling, poor, or never predicted (labels with eval rows)."""
    out = {}
    for kind in ("tactic", "technique"):
        chosen = [r for r in rows if r["kind"] == kind]
        scored = [r for r in chosen if r["eval_support"] > 0]
        f1 = [r["f1"] or 0.0 for r in scored]
        out[kind] = {
            "labels": len(chosen),
            "with_eval_rows": len(scored),
            "f1_at_least_0.8": sum(v >= 0.8 for v in f1),
            "f1_0.5_to_0.8": sum(0.5 <= v < 0.8 for v in f1),
            "f1_under_0.5": sum(v < 0.5 for v in f1),
            "never_predicted": sum(r["predicted"] == 0 for r in scored),
            "in_eval_but_not_in_train": [r["label"] for r in scored if r["train_support"] == 0],
        }
    return out
