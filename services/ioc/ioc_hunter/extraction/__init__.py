"""Public extraction API; optional dependencies load only when used."""
from .pipeline import ExtractionResult, extract_report, create_sentencizer
from .datasets import load_reports

__all__ = ["ExtractionResult", "extract_report", "create_sentencizer", "load_reports"]
