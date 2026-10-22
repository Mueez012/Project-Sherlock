import math

import torch
from torch.distributions import MultivariateNormal

from ttp_extraction.gaussian.prototypes import GaussianPrototypes

N_LABELS, D = 3, 5


def make() -> GaussianPrototypes:
    torch.manual_seed(0)
    g = GaussianPrototypes(N_LABELS, D).double()
    with torch.no_grad():
        g.mu.normal_(std=0.3)
        g.raw_tril.normal_(std=0.3)
        g.raw_diag.normal_()
    return g


def inputs(batch: int = 2, steps: int = 4):
    H = 0.3 * torch.randn(batch, steps, D, dtype=torch.float64)
    return H, torch.ones(batch, steps, dtype=torch.bool)


def test_shapes():
    g = make()
    T_rep, S = g(*inputs())
    assert T_rep.shape == (2, N_LABELS, D)
    assert S.shape == (2, N_LABELS, 4)


def test_similarity_is_one_at_the_mean():
    g = make()
    H = g.mu.detach().unsqueeze(0)                    # token l sits exactly on mu_l
    S = g.similarity(H, torch.ones(1, N_LABELS, dtype=torch.bool))
    assert torch.allclose(torch.diagonal(S[0]), torch.ones(N_LABELS, dtype=torch.float64))


def test_similarity_is_gaussian_density_without_its_constant():
    g = make()
    H, mask = inputs()
    S = g.similarity(H, mask)
    P = g.precision()
    for l in range(N_LABELS):
        density = MultivariateNormal(g.mu[l], precision_matrix=P[l])
        constant = 0.5 * D * math.log(2 * math.pi) - 0.5 * torch.logdet(P[l])
        expected = torch.exp(density.log_prob(H) + constant)
        assert torch.allclose(S[:, l], expected, rtol=1e-6, atol=1e-12)


def test_range_and_positive_definite_precision():
    g = make()
    S = g.similarity(*inputs())
    assert (S > 0).all() and (S <= 1).all()
    assert torch.linalg.eigvalsh(g.precision()).min() > 0


def test_masked_tokens_contribute_nothing():
    g = make()
    H, _ = inputs(batch=2, steps=6)
    mask = torch.tensor([[1, 1, 1, 1, 0, 0], [1, 1, 1, 1, 1, 1]], dtype=torch.bool)
    T_rep, S = g(H, mask)
    assert (S[0, :, 4:] == 0).all()
    T_short, _ = g(H[:1, :4], torch.ones(1, 4, dtype=torch.bool))
    assert torch.allclose(T_rep[0], T_short[0])


def test_label_representation_is_equation_4():
    g = make()
    H, mask = inputs()
    T_rep, S = g(H, mask)
    expected = torch.zeros_like(T_rep)
    for b in range(2):
        for l in range(N_LABELS):
            for t in range(4):
                expected[b, l] += S[b, l, t] * H[b, t]
    assert torch.allclose(T_rep, expected)


def test_default_initialisation_gives_usable_scores():
    torch.manual_seed(0)
    g = GaussianPrototypes()                          # 203 labels, 48 dimensions
    eye = torch.eye(48).expand(203, 48, 48)
    assert torch.allclose(g.precision(), eye, atol=1e-4)
    S = g.similarity(torch.zeros(1, 1, 48), torch.ones(1, 1, dtype=torch.bool))
    assert S.min() > 0.5


def test_gradients_are_finite():
    g = make()
    T_rep, _ = g(*inputs())
    T_rep.sum().backward()
    for parameter in (g.mu, g.raw_tril, g.raw_diag):
        assert parameter.grad is not None
        assert torch.isfinite(parameter.grad).all()