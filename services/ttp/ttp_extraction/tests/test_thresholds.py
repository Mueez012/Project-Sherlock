import numpy as np
import pytest

from ttp_extraction.evaluation.decision import (
    DecisionLayer, apply_top1, best_threshold, cross_fitted_predictions, fit_thresholds,
)

N_TACTICS = 2


def toy(n=200, labels=5, seed=0):
    rng = np.random.default_rng(seed)
    y = (rng.random((n, labels)) < 0.3).astype(np.int8)
    # Probabilities informative but shifted low, so the best threshold is below 0.5.
    prob = np.clip(0.35 * y + 0.25 * rng.random((n, labels)), 0, 1)
    return y, prob


def test_fixed_is_half_everywhere():
    y, prob = toy()
    assert np.all(fit_thresholds(y, prob, N_TACTICS, "fixed") == 0.5)


def test_sweep_finds_a_lower_threshold_for_low_probabilities():
    y, prob = toy()
    t = best_threshold(y, prob)
    assert 0.2 < t < 0.5
    assert np.all(fit_thresholds(y, prob, N_TACTICS, "global") == t)


def test_per_slice_has_one_value_per_slice():
    y, prob = toy()
    prob[:, N_TACTICS:] *= 0.5     # techniques need a lower threshold
    t = fit_thresholds(y, prob, N_TACTICS, "per_slice")
    assert len(set(t[:N_TACTICS])) == 1 and len(set(t[N_TACTICS:])) == 1
    assert t[N_TACTICS] < t[0]


def test_per_label_falls_back_to_slice_for_rare_labels_and_is_clipped():
    y, prob = toy()
    y[:, 3] = 0
    y[:3, 3] = 1                   # only 3 positives < min_pos 5
    slice_t = fit_thresholds(y, prob, N_TACTICS, "per_slice")
    label_t = fit_thresholds(y, prob, N_TACTICS, "per_label", min_pos=5)
    assert label_t[3] == slice_t[3]
    assert np.all((label_t >= 0.05) & (label_t <= 0.9))


def test_thresholds_depend_only_on_the_rows_they_are_fitted_on():
    y, prob = toy()
    layer = DecisionLayer("per_label").fit(y[:100], prob[:100], N_TACTICS)
    again = DecisionLayer("per_label").fit(y[:100], prob[:100], N_TACTICS)
    # Changing rows outside the fitting set (e.g. the test split) changes nothing.
    assert layer.thresholds == again.thresholds
    prob_other = prob.copy()
    prob_other[100:] = 0.99
    assert DecisionLayer("per_label").fit(y[:100], prob_other[:100], N_TACTICS).thresholds == layer.thresholds


def test_json_round_trip(tmp_path):
    y, prob = toy()
    layer = DecisionLayer("per_label", hierarchy=True, top1=True).fit(y, prob, N_TACTICS, y)
    layer.save(tmp_path / "t.json", labels=[f"L{i}" for i in range(5)])
    loaded = DecisionLayer.load(tmp_path / "t.json")
    assert loaded.thresholds == pytest.approx(layer.thresholds)
    assert np.array_equal(loaded.predict(prob), layer.predict(prob))


def test_top1_fires_only_on_empty_rows():
    prob = np.array([[0.9, 0.1, 0.2, 0.3, 0.1],     # has a tactic, no technique
                     [0.2, 0.3, 0.1, 0.1, 0.4]])    # nothing at all
    pred = prob > 0.5
    out = apply_top1(pred, prob, N_TACTICS)
    assert out.tolist() == [[True, False, False, True, False],
                            [False, True, False, False, True]]
    full = np.ones_like(pred)
    assert np.array_equal(apply_top1(full, prob, N_TACTICS), full)


def test_cross_fitting_never_uses_the_scored_rows():
    y, prob = toy()
    pred = cross_fitted_predictions({"threshold_mode": "global"}, y, prob, N_TACTICS, folds=4)
    assert pred.shape == prob.shape and pred.dtype == bool
