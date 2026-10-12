"""TTP extraction (owner: TTP Extractor teammate)."""

from threatmamba.ttp.base import TTPExtractor
from threatmamba.ttp.keyword_extractor import KeywordTTPExtractor

__all__ = ["KeywordTTPExtractor", "TTPExtractor"]
