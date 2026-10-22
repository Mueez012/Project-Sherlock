import torch
import torch.nn.functional as F

from ttp_extraction.mamba.s6 import S6, TTPStateSpace


def randomise_A(ssm: S6) -> None:
    with torch.no_grad():
        ssm.A_sym.add_(0.3 * torch.randn_like(ssm.A_sym))
        ssm.A_skew.add_(0.3 * torch.randn_like(ssm.A_skew))


def small_stack() -> TTPStateSpace:
    torch.manual_seed(0)
    return TTPStateSpace(d_input=16, d_model=8, d_state=4, n_layers=3).double().eval()


def test_output_shape():
    out = TTPStateSpace()(torch.randn(2, 7, 768))
    assert out.shape == (2, 7, 48)


def test_A_starts_at_mamba_init_and_stays_stable():
    torch.manual_seed(0)
    ssm = S6(d_model=6, d_state=4)
    assert torch.allclose(ssm.A(), -torch.diag(torch.arange(1.0, 5.0)), atol=1e-5)
    randomise_A(ssm)
    A = ssm.A()
    assert torch.linalg.eigvalsh((A + A.T) / 2).max() < 0


def test_forward_matches_literal_equation_2():
    torch.manual_seed(0)
    ssm = S6(d_model=6, d_state=4).double()
    randomise_A(ssm)
    x = torch.randn(1, 5, 6, dtype=torch.float64)

    A, eye = ssm.A(), torch.eye(4, dtype=torch.float64)
    h = torch.zeros(4, 6, dtype=torch.float64)
    expected = []
    for t in range(5):
        e = x[0, t]                                   # (6,)
        delta = F.softplus(ssm.to_delta(e))           # (1,)
        B = ssm.to_B(e).unsqueeze(1)                  # (4, 1)
        C = ssm.to_C(e).unsqueeze(0)                  # (1, 4)
        A_bar = torch.linalg.matrix_exp(delta * A)
        B_bar = torch.linalg.inv(delta * A) @ (A_bar - eye) @ (delta * B)
        h = A_bar @ h + B_bar @ e.unsqueeze(0)        # (4, 6)
        expected.append((C @ h).squeeze(0))

    assert torch.allclose(ssm(x)[0], torch.stack(expected), atol=1e-9)


def test_model_is_causal():
    model = small_stack()
    x = torch.randn(2, 10, 16, dtype=torch.float64)
    changed = x.clone()
    changed[:, 6:] += 1.0
    assert torch.allclose(model(x)[:, :6], model(changed)[:, :6], atol=1e-10)


def test_right_padding_does_not_change_real_tokens():
    model = small_stack()
    x = torch.randn(2, 5, 16, dtype=torch.float64)
    padded = torch.cat([x, torch.zeros(2, 4, 16, dtype=torch.float64)], dim=1)
    assert torch.allclose(model(x), model(padded)[:, :5], atol=1e-10)


def test_gradients_are_finite_for_every_parameter():
    torch.manual_seed(0)
    model = TTPStateSpace(d_input=16, d_model=8, d_state=4, n_layers=3)
    model(torch.randn(2, 12, 16)).pow(2).mean().backward()
    for name, parameter in model.named_parameters():
        assert parameter.grad is not None, name
        assert torch.isfinite(parameter.grad).all(), name

def test_discretize_survives_a_singular_A():
    ssm = S6(d_model=3, d_state=4).double()
    with torch.no_grad():                      # A = 0: not invertible
        ssm.A_sym.zero_()
        ssm.A_skew.zero_()
        ssm.eps = 0.0
    delta = torch.full((2, 5, 1), 0.3, dtype=torch.float64)
    B = torch.randn(2, 5, 4, dtype=torch.float64)
    A_bar, B_bar = ssm.discretize(delta, B)
    # limit of (dA)^-1 (exp(dA) - I) dB as A -> 0 is dB
    assert torch.allclose(A_bar, torch.eye(4, dtype=torch.float64).expand_as(A_bar))
    assert torch.allclose(B_bar, 0.3 * B)
