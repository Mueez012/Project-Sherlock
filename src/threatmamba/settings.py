"""Runtime switches, read from environment variables on every request."""

import os
from enum import StrEnum


class Mode(StrEnum):
    stub = "stub"  # baseline extractors, no trained models, no downloads, no external APIs
    real = "real"  # call the module's service container; an unreachable service is an error, never a silent stub


def mode() -> Mode:
    """Default for every module: TM_MODEL_MODE."""
    return Mode(os.environ.get("TM_MODEL_MODE", "stub"))


def ttp_mode() -> Mode:
    """TM_TTP_MODE, falling back to TM_MODEL_MODE, so each service can be switched on when it is integrated."""
    return Mode(os.environ.get("TM_TTP_MODE") or mode())


def ioc_mode() -> Mode:
    """TM_IOC_MODE, falling back to TM_MODEL_MODE."""
    return Mode(os.environ.get("TM_IOC_MODE") or mode())


def ttp_url() -> str:
    return os.environ.get("TM_TTP_URL", "http://ttp:8001")


def ioc_url() -> str:
    return os.environ.get("TM_IOC_URL", "http://ioc:8002")


def ttp_timeout_s() -> float:
    return float(os.environ.get("TM_TTP_TIMEOUT_S", "600"))


def ioc_timeout_s() -> float:
    return float(os.environ.get("TM_IOC_TIMEOUT_S", "120"))
