import numpy as np
import pytest

from ttp_extraction.preprocessing.tokenization import MAX_LENGTH, encode, load_tokenizer


@pytest.fixture(scope="module")
def tokenizer():
    return load_tokenizer()


def test_shapes_and_dtypes(tokenizer):
    out = encode(tokenizer, ["short", "a much longer sentence about credential dumping"])
    assert out["input_ids"].shape == out["attention_mask"].shape
    assert out["input_ids"].shape[0] == 2
    assert out["input_ids"].dtype == np.int64


def test_mask_marks_exactly_the_real_tokens(tokenizer):
    out = encode(tokenizer, ["short", "a much longer sentence about credential dumping"])
    is_real = out["input_ids"] != tokenizer.pad_token_id
    assert np.array_equal(is_real, out["attention_mask"].astype(bool))


def test_special_tokens_are_kept(tokenizer):
    out = encode(tokenizer, ["short", "a much longer sentence about credential dumping"])
    lengths = out["attention_mask"].sum(axis=1)
    for row, n in zip(out["input_ids"], lengths):
        assert row[0] == tokenizer.bos_token_id
        assert row[n - 1] == tokenizer.eos_token_id


def test_long_text_is_capped(tokenizer):
    out = encode(tokenizer, ["malware " * 1000])
    assert out["input_ids"].shape[1] == MAX_LENGTH