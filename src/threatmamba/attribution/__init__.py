"""Threat actor attribution (GAT + MAMBA + contrastive learning, paper Sec. III-B). Not trained yet."""

from threatmamba.contracts import CSKG, Attribution


def attribute(graph: CSKG | None) -> Attribution | None:
    """Stub: no trained classifier exists, so no attribution is returned rather than a fake one."""
    return None
