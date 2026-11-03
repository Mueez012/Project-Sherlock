"""Local paths and environment configuration shared by entry points.

Credentials are read when a client is created, never at import time.
"""
import os
from pathlib import Path

PROJECT_DIRECTORY = Path(__file__).resolve().parents[1]
DATASET_DIRECTORY = PROJECT_DIRECTORY.parent / "ThreatMamba-Datasets" / "ThreatMAMBA-main"
DEFAULT_DATASET = DATASET_DIRECTORY / "cleaned_CTI2Attacker(main).csv"
DEFAULT_LOOKUP_DIRECTORY = PROJECT_DIRECTORY / "output" / "lookups"


def api_keys_from_environment() -> dict[str, str]:
    from .providers import PROVIDERS
    return {name: os.environ.get(provider.API_KEY_ENV, "")
            for name, provider in PROVIDERS.items() if provider.API_KEY_ENV}
