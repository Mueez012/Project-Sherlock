import math

import numpy as np
import pytest
import torch
import torch.nn.functional as F

from ttp_extraction.training.focal_loss import FocalBCEWithLogitsLoss
from ttp_extraction.training.losses import AsymmetricLoss, build_loss, positive_weights

LOGITS = torch.tensor([[2.0, -1.0, 0.3], [-3.0, 0.5, 1.5]])
TARGETS = torch.tensor([[1.0, 0.0, 1.0], [0.0, 0.0, 1.0]])


def test_focal_with_gamma_zero_is_bce():
    focal = FocalBCEWithLogitsLoss(gamma=0.0)(LOGITS, TARGETS)
    assert focal.item() == pytest.approx(F.binary_cross_entropy_with_logits(LOGITS, TARGETS).item())


def test_bce_loss_is_the_paper_loss():
    loss = build_loss("bce", None)(LOGITS, TARGETS)
    assert loss.item() == pytest.approx(F.binary_cross_entropy_with_logits(LOGITS, TARGETS).item())


def test_asl_matches_hand_calculation():
    logit_pos, logit_neg = torch.tensor([[0.4]]), torch.tensor([[0.2]])
    p_pos, p_neg = 1 / (1 + math.exp(-0.4)), 1 / (1 + math.exp(-0.2))
    asl = AsymmetricLoss(gamma_neg=4.0, gamma_pos=1.0, clip=0.05)
    expected_pos = -(1 - p_pos) ** 1 * math.log(p_pos)
    pm = p_neg - 0.05
    expected_neg = -(pm ** 4) * math.log(1 - pm)
    assert asl(logit_pos, torch.ones(1, 1)).item() == pytest.approx(expected_pos, rel=1e-5)
    assert asl(logit_neg, torch.zeros(1, 1)).item() == pytest.approx(expected_neg, rel=1e-5)


def test_asl_ignores_very_easy_negatives():
    asl = AsymmetricLoss(clip=0.05)
    assert asl(torch.tensor([[-5.0]]), torch.zeros(1, 1)).item() == 0.0   # p = 0.0067 < clip


def test_asl_without_asymmetry_is_bce():
    asl = AsymmetricLoss(gamma_neg=0.0, gamma_pos=0.0, clip=0.0)
    assert asl(LOGITS, TARGETS).item() == pytest.approx(
        F.binary_cross_entropy_with_logits(LOGITS, TARGETS).item(), rel=1e-5)


def test_pos_weight_uses_only_the_rows_given_and_is_capped():
    y_train = np.zeros((100, 3), dtype=np.int8)
    y_train[:50, 0] = 1      # balanced -> weight 1
    y_train[:4, 1] = 1       # rare -> sqrt(96/4) = 4.9
    y_train[:1, 2] = 1       # very rare -> sqrt(99) = 9.95, capped at 5
    w = positive_weights(y_train, "sqrt", cap=5.0)
    assert w.tolist() == pytest.approx([1.0, math.sqrt(24), 5.0], rel=1e-5)
    assert positive_weights(y_train, "none", 5.0) is None
    assert positive_weights(y_train, "log", 100.0)[2].item() == pytest.approx(1 + math.log(99), rel=1e-5)


def test_weighted_bce_requires_a_weight_scheme():
    with pytest.raises(ValueError):
        build_loss("weighted_bce", None)
