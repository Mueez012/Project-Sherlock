import numpy as np

from ttp_extraction.evaluation.decision import DecisionLayer, apply_hierarchy, technique_to_tactics

N_TACTICS = 2
# columns: tactic A, tactic B, technique 0, technique 1, technique 2
Y_TRAIN = np.array([
    [1, 0, 1, 0, 0],
    [1, 0, 1, 0, 0],
    [1, 1, 0, 1, 0],
    [0, 1, 0, 1, 0],
    [1, 0, 1, 0, 0],
], dtype=np.int8)


def test_map_comes_from_training_rows():
    mapping = technique_to_tactics(Y_TRAIN, N_TACTICS, min_share=0.5)
    assert mapping == {2: [0], 3: [0, 1]}        # technique 2 never seen: no entry
    assert technique_to_tactics(Y_TRAIN, N_TACTICS, min_share=0.9) == {2: [0], 3: [1]}


def test_hierarchy_only_adds_labels():
    mapping = technique_to_tactics(Y_TRAIN, N_TACTICS)
    rng = np.random.default_rng(0)
    pred = rng.random((50, 5)) < 0.3
    out = apply_hierarchy(pred, mapping)
    assert np.all(out >= pred)                     # nothing removed
    assert np.array_equal(out[:, N_TACTICS:], pred[:, N_TACTICS:])   # techniques untouched
    rows = pred[:, 3]
    assert out[rows, 0].all() and out[rows, 1].all()


def test_layer_uses_train_labels_not_validation_labels():
    y_val = np.zeros((4, 5), dtype=np.int8)
    prob = np.full((4, 5), 0.1)
    prob[0, 2] = 0.9
    layer = DecisionLayer("fixed", hierarchy=True).fit(y_val, prob, N_TACTICS, Y_TRAIN)
    assert layer.predict(prob)[0].tolist() == [True, False, True, False, False]
