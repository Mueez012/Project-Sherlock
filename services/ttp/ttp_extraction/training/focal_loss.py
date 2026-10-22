"""Focal loss for multi-label classification with class imbalance.

Lin et al., 'Focal Loss for Dense Object Detection', ICCV 2017.
Adapted for multi-label BCE: applies per-class focusing and optional
positive-class weighting to help rare technique labels.
"""
from __future__ import annotations

import numpy as np
import torch
import torch.nn.functional as F
from torch import nn


class FocalBCEWithLogitsLoss(nn.Module):
    """Focal modulation of binary cross-entropy.

    L = -alpha_t (1 - p_t)^gamma log(p_t)

    gamma > 0 down-weights easy (well-classified) examples.
    pos_weight optionally up-weights positive examples per class.
    """

    def __init__(self, gamma: float = 2.0, pos_weight: torch.Tensor | None = None,
                 reduction: str = "mean"):
        super().__init__()
        self.gamma = gamma
        self.reduction = reduction
        if pos_weight is not None:
            self.register_buffer("pos_weight", pos_weight)
        else:
            self.pos_weight = None

    def forward(self, logits: torch.Tensor, targets: torch.Tensor) -> torch.Tensor:
        """logits, targets: (B, L). Returns scalar loss."""
        # Numerically stable BCE per element.
        bce = F.binary_cross_entropy_with_logits(logits, targets, reduction="none")

        # p_t = probability of the correct class.
        p = torch.sigmoid(logits)
        p_t = p * targets + (1 - p) * (1 - targets)

        # Focal modulation: down-weight easy examples.
        focal_weight = (1 - p_t) ** self.gamma
        loss = focal_weight * bce

        # Per-class positive weighting for rare labels.
        if self.pos_weight is not None:
            class_weight = targets * self.pos_weight + (1 - targets)
            loss = loss * class_weight

        if self.reduction == "mean":
            return loss.mean()
        if self.reduction == "sum":
            return loss.sum()
        return loss


def compute_pos_weight(y_train: np.ndarray, cap: float = 10.0) -> torch.Tensor:
    """Per-label positive weight from training labels.

    weight_l = sqrt(neg_count_l / (pos_count_l + 1)), capped at `cap`.
    Rare labels get higher weight; common ones stay near 1.
    """
    pos = y_train.sum(axis=0).astype(float)
    neg = len(y_train) - pos
    weight = np.sqrt(neg / (pos + 1))
    weight = np.clip(weight, 1.0, cap)
    return torch.from_numpy(weight).float()
