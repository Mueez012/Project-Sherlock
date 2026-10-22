import torch
import torch.nn.functional as F

from ttp_extraction.classifier.model import TTPExtractor

N_LABELS, D_INPUT, D_MODEL = 6, 16, 8


def small(per_label: bool = False) -> TTPExtractor:
    torch.manual_seed(0)
    return TTPExtractor(n_labels=N_LABELS, d_input=D_INPUT, d_model=D_MODEL, d_state=4,
                        n_layers=2, per_label_classifier=per_label).double().eval()


def batch(steps: int = 6):
    torch.manual_seed(1)
    embeddings = torch.randn(2, steps, D_INPUT, dtype=torch.float64)
    mask = torch.ones(2, steps, dtype=torch.bool)
    return embeddings, mask


def test_output_shapes_and_probability_range():
    out = small()(*batch())
    assert out["logits"].shape == (2, N_LABELS)
    assert out["label_repr"].shape == (2, N_LABELS, D_MODEL)
    assert out["similarity"].shape == (2, N_LABELS, 6)
    assert out["hidden"].shape == (2, 6, D_MODEL)
    assert torch.allclose(out["probabilities"], torch.sigmoid(out["logits"]))
    assert (out["probabilities"] > 0).all() and (out["probabilities"] < 1).all()


def test_shared_classifier_is_equation_5():
    model = small()
    out = model(*batch())
    weight, bias = model.classifier.linear.weight[0], model.classifier.linear.bias
    assert torch.allclose(out["logits"], out["label_repr"] @ weight + bias)
    assert sum(p.numel() for p in model.classifier.parameters()) == D_MODEL + 1


def test_per_label_classifier():
    model = small(per_label=True)
    out = model(*batch())
    expected = (out["label_repr"] * model.classifier.weight).sum(-1) + model.classifier.bias
    assert torch.allclose(out["logits"], expected)
    assert sum(p.numel() for p in model.classifier.parameters()) == N_LABELS * D_MODEL + N_LABELS


def test_padding_content_does_not_change_predictions():
    model = small()
    embeddings, mask = batch()
    mask[0, 4:] = False
    garbage = embeddings.clone()
    garbage[0, 4:] = torch.randn(2, D_INPUT, dtype=torch.float64)
    alone = model(embeddings[:1, :4], torch.ones(1, 4, dtype=torch.bool))["logits"][0]
    assert torch.allclose(model(embeddings, mask)["logits"][0], alone, atol=1e-10)
    assert torch.allclose(model(garbage, mask)["logits"][0], alone, atol=1e-10)


def test_predictions_do_not_depend_on_batch_mates():
    model = small()
    embeddings, mask = batch()
    together = model(embeddings, mask)["logits"][0]
    alone = model(embeddings[:1], mask[:1])["logits"][0]
    assert torch.allclose(together, alone, atol=1e-10)


def test_every_parameter_receives_a_finite_gradient():
    model = small().train()
    out = model(*batch())
    targets = torch.zeros(2, N_LABELS, dtype=torch.float64)
    targets[0, 1] = targets[1, 4] = 1.0
    F.binary_cross_entropy_with_logits(out["logits"], targets).backward()
    for name, parameter in model.named_parameters():
        assert parameter.grad is not None, name
        assert torch.isfinite(parameter.grad).all(), name