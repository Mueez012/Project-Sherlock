import numpy as np

from ttp_extraction.data.batching import pad_batch


def test_pad_batch_shapes_mask_and_zero_padding():
    short, long = np.ones((2, 4), dtype=np.float32), np.ones((5, 4), dtype=np.float32)
    embeddings, mask = pad_batch([short, long])
    assert embeddings.shape == (2, 5, 4)
    assert mask.tolist() == [[True, True, False, False, False], [True] * 5]
    assert (embeddings[0, 2:] == 0).all()
    assert (embeddings[1] == 1).all()