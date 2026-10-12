"""Interface the TTP Extractor (SecureBERT + SSM + Gaussian prototypes, paper Sec. III-A2) must satisfy.

Output technique IDs must come from the 189-technique vocabulary in the Phase 1 manifest (ttp_vocab).
"""

from typing import Protocol

from threatmamba.contracts import TTPHit


class TTPExtractor(Protocol):
    def predict(self, sentences: list[str]) -> list[TTPHit]: ...
