"""Runtime switches, read from environment variables."""

import os
from enum import StrEnum


class Mode(StrEnum):
    stub = "stub"  # baseline extractors, no trained models, no downloads, no external APIs
    real = "real"  # trained checkpoints (not available yet)


def mode() -> Mode:
    return Mode(os.environ.get("TM_MODEL_MODE", "stub"))
