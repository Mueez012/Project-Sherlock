import math

import numpy as np
import torch

from ttp_extraction.classifier.model import TTPExtractorE2E
from ttp_extraction.training.focal_loss import FocalBCEWithLogitsLoss
from ttp_extraction.training.train_finetune import FinetuneConfig, build_optimizer, is_update_step


def tiny_encoder():
    from transformers import RobertaConfig, RobertaModel

    torch.manual_seed(0)
    config = RobertaConfig(vocab_size=50, hidden_size=16, num_hidden_layers=2,
                           num_attention_heads=2, intermediate_size=32, max_position_embeddings=40)
    return RobertaModel(config)


def test_one_finetune_step_on_cpu_updates_encoder_and_head():
    model = TTPExtractorE2E(tiny_encoder(), n_labels=5, d_model=8, d_state=2, n_layers=1)
    optimizer = build_optimizer(model, FinetuneConfig())
    ids = torch.randint(3, 50, (4, 7))
    mask = torch.ones(4, 7, dtype=torch.long)
    mask[1, 5:] = 0
    targets = (torch.rand(4, 5) < 0.4).float()
    before = {n: p.detach().clone() for n, p in model.named_parameters()}
    loss = FocalBCEWithLogitsLoss(gamma=2.0)(model(ids, mask)["logits"], targets)
    loss.backward()
    optimizer.step()
    assert torch.isfinite(loss)
    changed = {n for n, p in model.named_parameters() if not torch.equal(p, before[n])}
    assert any(n.startswith("encoder.") for n in changed)
    assert any(n.startswith("head.") for n in changed)


def test_trimming_padding_does_not_change_outputs():
    from ttp_extraction.training.train_finetune import trim

    model = TTPExtractorE2E(tiny_encoder(), n_labels=5, d_model=8, d_state=2, n_layers=1).eval()
    ids = torch.randint(3, 50, (3, 12))
    mask = torch.zeros(3, 12, dtype=torch.long)
    mask[0, :5], mask[1, :3], mask[2, :6] = 1, 1, 1
    ids[mask == 0] = 1
    with torch.no_grad():
        full = model(ids, mask)["logits"]
        short = model(*trim(ids, mask))["logits"]
    assert trim(ids, mask)[0].shape[1] == 6
    assert torch.allclose(full, short, atol=1e-5)


def test_unfreeze_top_only_trains_the_top_layers():
    from ttp_extraction.training.train_finetune import freeze_lower_layers

    encoder = tiny_encoder()
    freeze_lower_layers(encoder, 1)
    trainable = {n.split(".")[2] for n, p in encoder.named_parameters()
                 if p.requires_grad and n.startswith("encoder.layer.")}
    assert trainable == {"1"}
    assert not any(p.requires_grad for p in encoder.embeddings.parameters())


def test_gradient_accumulation_steps_on_the_last_batch():
    for n_rows, batch_size, accumulation in [(64, 8, 4), (60, 8, 4), (8, 8, 4), (100, 8, 3)]:
        n_batches = math.ceil(n_rows / batch_size)
        steps = [i for i in range(n_batches) if is_update_step(i, n_batches, accumulation)]
        assert steps[-1] == n_batches - 1, (n_rows, batch_size, accumulation)
        assert len(steps) == math.ceil(n_batches / accumulation)
