"""Interfaces the IOCHunter implementation must satisfy.

Every external service (VirusTotal, AlienVault OTX, RapidDNS, the LLM) goes behind HuntingSource so CI can
replace it with recorded responses and never needs API keys.
"""

from typing import Protocol

from threatmamba.contracts import IOC, IOCEdge


class IOCExtractor(Protocol):
    def extract(self, sentences: list[str]) -> list[IOC]: ...


class HuntingSource(Protocol):
    name: str

    def expand(self, ioc: IOC) -> list[tuple[IOC, IOCEdge]]:
        """Return new IOCs connected to `ioc`, each with the edge that links them."""
        ...
