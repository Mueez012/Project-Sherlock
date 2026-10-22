import numpy as np
import pytest

from ttp_extraction.evaluation.metrics import evaluate_predictions, slice_report

# Label 0: tp 2, fp 1, fn 1 -> P 2/3, R 2/3, F1 2/3
# Label 1: tp 1, fp 0, fn 1 -> P 1,   R 1/2, F1 2/3
Y_TRUE = np.array([[1, 0], [1, 1], [0, 1], [1, 0]], dtype=np.int8)
PROB = np.array([[0.9, 0.1], [0.8, 0.4], [0.7, 0.6], [0.2, 0.3]])


def test_micro_and_macro_match_hand_calculation():
    report = slice_report(Y_TRUE, PROB)
    assert report["micro"] == pytest.approx({"precision": 75.0, "recall": 60.0, "f1": 200 / 3})
    assert report["macro"] == pytest.approx(
        {"precision": 250 / 3, "recall": 175 / 3, "f1": 200 / 3}
    )


def test_micro_f1_is_the_harmonic_mean_of_micro_p_and_r():
    # Table VI reports F1 as the harmonic mean of its P and R; ours must agree.
    rng = np.random.default_rng(0)
    y = (rng.random((40, 7)) < 0.3).astype(np.int8)
    prob = rng.random((40, 7))
    m = slice_report(y, prob)["micro"]
    assert m["f1"] == pytest.approx(2 * m["precision"] * m["recall"] / (m["precision"] + m["recall"]))
    p, r = 89.75, 86.83   # Table VI tactics
    assert 2 * p * r / (p + r) == pytest.approx(88.26, abs=0.01)


def test_per_label_rows_and_buckets():
    from ttp_extraction.evaluation.metrics import per_label_rows, quality_summary, support_buckets
    supports = {"train": np.array([50, 5, 200]), "val": np.zeros(3), "test": np.zeros(3)}
    y = np.array([[1, 1, 0], [1, 0, 1], [0, 0, 1]], dtype=np.int8)
    pred = np.array([[1, 0, 0], [1, 0, 1], [0, 0, 0]], dtype=bool)
    rows = per_label_rows(y, pred, ["TA1", "T1", "T2"], 1, supports, thresholds=[0.5] * 3)
    assert [r["label"] for r in rows] == ["TA1", "T1", "T2"]   # tactics first, then rarest
    t1 = rows[1]
    assert (t1["f1"], t1["predicted"], t1["eval_support"]) == (0.0, 0, 1)
    assert rows[2]["f1"] == pytest.approx(2 / 3)
    buckets = support_buckets(rows)
    assert buckets["<10"]["labels"] == 1 and buckets["100+"]["macro_f1"] == pytest.approx(200 / 3)
    assert quality_summary(rows)["technique"]["never_predicted"] == 1


def test_labels_without_support_are_counted_explicitly():
    y_true = np.hstack([Y_TRUE, np.zeros((4, 1), dtype=np.int8)])
    prob = np.hstack([PROB, np.zeros((4, 1))])
    report = slice_report(y_true, prob)
    assert report["labels"] == 3
    assert report["labels_with_support"] == 2
    assert report["macro"]["f1"] == pytest.approx(400 / 9)
    assert report["macro_supported_labels"]["f1"] == pytest.approx(200 / 3)
    assert report["micro"]["f1"] == pytest.approx(200 / 3)


def test_tactic_and_technique_slices_are_separate():
    report = evaluate_predictions(Y_TRUE, PROB, n_tactics=1)
    # With a single column, sklearn treats this as binary classification;
    # micro average over both classes yields 50% for tactics, 75% for techniques.
    assert report["tactics"]["micro"]["f1"] == pytest.approx(50.0)
    assert report["techniques"]["micro"] == pytest.approx(
        {"precision": 75.0, "recall": 75.0, "f1": 75.0}
    )