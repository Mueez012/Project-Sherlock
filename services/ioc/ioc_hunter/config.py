"""Local paths and environment configuration shared by entry points.

Credentials are read when a client is created, never at import time.
"""
import os
from pathlib import Path

PROJECT_DIRECTORY = Path(__file__).resolve().parents[1]


def default_dataset() -> Path:
    """Keep standalone installs and the existing FYP checkout usable after relocation.

    An explicit --dataset or IOC_HUNTER_DATASET remains the portable choice.
    Never substitute a different dataset or rebuild the committed cleaned splits.
    """
    configured = os.environ.get("IOC_HUNTER_DATASET")
    if configured:
        return Path(configured).expanduser()
    relative = Path("ThreatMamba-Datasets") / "ThreatMAMBA-main" / "cleaned_CTI2Attacker(main).csv"
    original = PROJECT_DIRECTORY.parent / relative
    if original.is_file():
        return original
    for ancestor in PROJECT_DIRECTORY.parents:
        candidate = ancestor / "code" / relative
        if candidate.is_file():
            return candidate
    return original


DEFAULT_DATASET = default_dataset()
DATASET_DIRECTORY = DEFAULT_DATASET.parent
DEFAULT_LOOKUP_DIRECTORY = PROJECT_DIRECTORY / "output" / "lookups"


def api_keys_from_environment() -> dict[str, str]:
    from .providers import PROVIDERS
    return {name: os.environ.get(provider.API_KEY_ENV, "")
            for name, provider in PROVIDERS.items() if provider.API_KEY_ENV}
