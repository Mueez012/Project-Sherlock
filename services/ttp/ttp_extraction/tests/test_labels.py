import numpy as np
import pandas as pd

from ttp_extraction.data.labels import LabelVocab, load_dataset


def write_csv(tmp_path):
    df = pd.DataFrame({
        "Text": ["a phishing email", "ran a script"],
        "TA0002": [0, 1], "TA0001": [1, 0],
        "T1566": [1, 0], "T1566.001": [1, 0], "T1059": [0, 1],
    })
    path = tmp_path / "toy.csv"
    df.to_csv(path, index=False, encoding="gb18030")
    return path


def test_vocab_is_sorted_and_excludes_subtechniques(tmp_path):
    _, _, vocab = load_dataset(write_csv(tmp_path))
    assert vocab.labels == ("TA0001", "TA0002", "T1059", "T1566")
    assert vocab.tactic_slice == slice(0, 2)
    assert vocab.technique_slice == slice(2, 4)


def test_label_matrix_follows_vocab_order(tmp_path):
    texts, y, _ = load_dataset(write_csv(tmp_path))
    assert texts == ["a phishing email", "ran a script"]
    assert y.dtype == np.int8
    assert y.tolist() == [[1, 0, 0, 1], [0, 1, 1, 0]]


def test_vocab_round_trip(tmp_path):
    vocab = LabelVocab(("TA0001",), ("T1059", "T1566"))
    vocab.save(tmp_path / "vocab.json")
    assert LabelVocab.load(tmp_path / "vocab.json") == vocab