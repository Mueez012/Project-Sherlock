"""The label matrix y, the saved vocabulary and the embedding cache must line up row by row.

Uses the real dataset and cache; skipped when they are not on this machine.
"""
from pathlib import Path

import numpy as np
import pytest

CSV = Path("ThreatMAMBA-main/CTI2TTPs.csv")
VOCAB = Path("artifacts/label_vocab.json")


@pytest.fixture(scope="module")
def data():
    from ttp_extraction.data.labels import load_dataset
    from ttp_extraction.securebert.cache import DEFAULT_ROOT, EmbeddingCache

    if not CSV.exists() or not (DEFAULT_ROOT / "offsets.npy").exists():
        pytest.skip("dataset or embedding cache not available")
    texts, y, vocab = load_dataset(CSV)
    return texts, y, vocab, EmbeddingCache(DEFAULT_ROOT)


def test_vocab_file_matches_the_csv_columns(data):
    from ttp_extraction.data.labels import LabelVocab

    _, y, vocab, _ = data
    assert LabelVocab.load(VOCAB) == vocab
    assert y.shape[1] == len(vocab) == 203
    assert all(t.startswith("TA") for t in vocab.tactics)
    assert not any(t.startswith("TA") for t in vocab.techniques)


def test_label_columns_hold_the_csv_values(data):
    import pandas as pd

    _, y, vocab, _ = data
    df = pd.read_csv(CSV, encoding="gb18030", low_memory=False)
    df.columns = [str(c).strip() for c in df.columns]
    rng = np.random.default_rng(0)
    for row in rng.choice(len(df), 50, replace=False):
        for j in rng.choice(len(vocab), 20, replace=False):
            assert y[row, j] == int(df.iloc[row][vocab.labels[j]])


def test_cache_rows_match_sentence_token_counts(data):
    from ttp_extraction.preprocessing.tokenization import MAX_LENGTH, load_tokenizer

    texts, y, _, cache = data
    assert len(cache) == len(texts) == len(y)
    tokenizer = load_tokenizer()
    rng = np.random.default_rng(1)
    for i in rng.choice(len(texts), 30, replace=False):
        n = len(tokenizer(texts[i], truncation=True, max_length=MAX_LENGTH)["input_ids"])
        assert cache[int(i)].shape == (n, 768), i


def test_every_row_has_a_tactic_and_a_technique(data):
    _, y, vocab, _ = data
    n_tactics = len(vocab.tactics)
    assert (y[:, :n_tactics].sum(axis=1) > 0).all()
    assert (y[:, n_tactics:].sum(axis=1) > 0).all()
