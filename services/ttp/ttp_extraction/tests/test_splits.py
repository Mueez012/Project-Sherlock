import numpy as np

from ttp_extraction.data.labels import LabelVocab
from ttp_extraction.data.splits import coverage, load_split, make_split, save_split


def test_sizes_match_paper():
    split = make_split(12406, seed=0)
    assert {k: len(v) for k, v in split.items()} == {"train": 10048, "val": 1117, "test": 1241}


def test_split_is_a_partition():
    split = make_split(12406, seed=0)
    merged = np.concatenate(list(split.values()))
    assert np.array_equal(np.sort(merged), np.arange(12406))


def test_split_is_deterministic_per_seed():
    a, b, c = make_split(500, 0, 50), make_split(500, 0, 50), make_split(500, 1, 50)
    assert all(np.array_equal(a[k], b[k]) for k in a)
    assert not np.array_equal(a["test"], c["test"])


def test_split_round_trip(tmp_path):
    split = make_split(500, 0, 50)
    save_split(split, 0, tmp_path / "s.json")
    loaded = load_split(tmp_path / "s.json")
    assert all(np.array_equal(split[k], loaded[k]) for k in split)


def test_coverage_counts_unseen_test_technique():
    vocab = LabelVocab(("TA0001",), ("T1059", "T1566"))
    y = np.array([[1, 1, 0], [1, 1, 0], [1, 0, 1]], dtype=np.int8)
    split = {"train": np.array([0]), "val": np.array([1]), "test": np.array([2])}
    report = coverage(y, split, vocab)
    assert report["test_techniques_unseen_in_train"] == 1
    assert report["test_rows_with_unseen_technique"] == 1