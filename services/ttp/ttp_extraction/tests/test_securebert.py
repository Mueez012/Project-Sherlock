import numpy as np
import pytest
import torch

from ttp_extraction.preprocessing.tokenization import encode, load_tokenizer
from ttp_extraction.securebert.cache import build_cache
from ttp_extraction.securebert.encoder import HIDDEN_SIZE, embed, load_encoder

TEXTS = [
    "short",
    "a much longer sentence about credential dumping with Mimikatz",
    "It dropped evil.exe to disk.",
]


@pytest.fixture(scope="module")
def tokenizer():
    return load_tokenizer()


@pytest.fixture(scope="module")
def encoder():
    return load_encoder(device=torch.device("cpu"))


def test_output_is_token_level(tokenizer, encoder):
    batch = encode(tokenizer, TEXTS)
    out = embed(encoder, batch)
    assert out.shape == (3, batch["input_ids"].shape[1], HIDDEN_SIZE)


def test_encoder_is_frozen(encoder):
    assert not encoder.training
    assert all(not p.requires_grad for p in encoder.parameters())


def test_padding_does_not_change_real_tokens(tokenizer, encoder):
    alone = embed(encoder, encode(tokenizer, TEXTS[:1]))[0]
    batched = embed(encoder, encode(tokenizer, TEXTS))[0, : alone.shape[0]]
    assert torch.allclose(alone, batched, atol=1e-4)


def test_cache_matches_live_embeddings(tokenizer, encoder, tmp_path):
    cache = build_cache(TEXTS, tokenizer, encoder, tmp_path, batch_size=2)
    assert len(cache) == 3
    for i, text in enumerate(TEXTS):
        live = embed(encoder, encode(tokenizer, [text]))[0].numpy()
        assert cache[i].shape == live.shape
        assert np.allclose(cache[i], live, atol=1e-4)

def test_layer_choices(tokenizer, encoder):
    batch = encode(tokenizer, TEXTS)
    hidden = encoder(input_ids=torch.from_numpy(batch["input_ids"]),
                     attention_mask=torch.from_numpy(batch["attention_mask"]),
                     output_hidden_states=True).hidden_states
    assert torch.allclose(embed(encoder, batch, "last"), hidden[-1], atol=1e-5)
    assert torch.allclose(embed(encoder, batch, "last4_mean"), torch.stack(hidden[-4:]).mean(0), atol=1e-5)
    assert embed(encoder, batch, "last4_concat").shape[-1] == 4 * HIDDEN_SIZE
