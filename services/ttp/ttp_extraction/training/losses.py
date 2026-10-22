"""Training losses for the 203-label multi-label task (Phase 3).

  bce           plain binary cross-entropy (the paper)
  weighted_bce  BCE with a per-label positive weight (rare labels count more)
  focal         focal loss (Lin et al., 2017): down-weights easy examples
  asl           asymmetric loss (Ridnik et al., 2021): built for multi-label
                tasks with many more negatives than positives. Easy negatives
                are down-weighted hard (gamma_neg) and very low negative
                probabilities are ignored entirely (clip).

Positive weights come from TRAINING rows only:
  sqrt  w_l = sqrt(neg_l / pos_l)       clipped to [1, cap]
  log   w_l = 1 + log(neg_l / pos_l)    clipped to [1, cap]
"""
from __future__ import annotations

import numpy as np
import torch
import torch.nn.functional as F
from torch import nn

from ttp_extraction.training.focal_loss import FocalBCEWithLogitsLoss

LOSSES = ("bce", "weighted_bce", "focal", "asl")
POS_WEIGHTS = ("none", "sqrt", "log")


def positive_weights(y_train: np.ndarray, scheme: str, cap: float) -> torch.Tensor | None:
    if scheme == "none":
        return None
    if scheme not in POS_WEIGHTS:
        raise ValueError(f"pos weight must be one of {POS_WEIGHTS}, got {scheme!r}")
    pos = np.maximum(y_train.sum(axis=0).astype(float), 1.0)
    ratio = (len(y_train) - pos) / pos
    weight = np.sqrt(ratio) if scheme == "sqrt" else 1.0 + np.log(np.maximum(ratio, 1.0))
    return torch.from_numpy(np.clip(weight, 1.0, cap)).float()


class AsymmetricLoss(nn.Module):
    """L = -[ y (1-p)^g+ log p + (1-y) p_m^g- log(1-p_m) ],  p_m = max(p - clip, 0).

    Averaged over all (sentence, label) cells, like BCE.
    """

    def __init__(self, gamma_neg: float = 4.0, gamma_pos: float = 0.0, clip: float = 0.05,
                 pos_weight: torch.Tensor | None = None, eps: float = 1e-8):
        super().__init__()
        self.gamma_neg, self.gamma_pos, self.clip, self.eps = gamma_neg, gamma_pos, clip, eps
        self.register_buffer("pos_weight", pos_weight if pos_weight is not None else None)

    def forward(self, logits: torch.Tensor, targets: torch.Tensor) -> torch.Tensor:
        p = torch.sigmoid(logits)
        p_neg = (p - self.clip).clamp(min=0) if self.clip > 0 else p
        loss_pos = targets * (1 - p).pow(self.gamma_pos) * torch.log(p.clamp(min=self.eps))
        loss_neg = (1 - targets) * p_neg.pow(self.gamma_neg) * torch.log((1 - p_neg).clamp(min=self.eps))
        if self.pos_weight is not None:
            loss_pos = loss_pos * self.pos_weight
        return -(loss_pos + loss_neg).mean()


def build_loss(name: str, pos_weight: torch.Tensor | None, focal_gamma: float = 2.0,
               asl_gamma_neg: float = 4.0, asl_gamma_pos: float = 0.0,
               asl_clip: float = 0.05) -> nn.Module:
    if name not in LOSSES:
        raise ValueError(f"loss must be one of {LOSSES}, got {name!r}")
    if name in ("bce", "weighted_bce"):
        if name == "weighted_bce" and pos_weight is None:
            raise ValueError("--loss weighted_bce needs --pos-weight sqrt or log")
        return nn.BCEWithLogitsLoss(pos_weight=pos_weight)
    if name == "focal":
        return FocalBCEWithLogitsLoss(gamma=focal_gamma, pos_weight=pos_weight)
    return AsymmetricLoss(asl_gamma_neg, asl_gamma_pos, asl_clip, pos_weight)


def plain_bce(logits: torch.Tensor, targets: torch.Tensor) -> torch.Tensor:
    return F.binary_cross_entropy_with_logits(logits, targets)
