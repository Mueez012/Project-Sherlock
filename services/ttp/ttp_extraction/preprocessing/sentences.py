"""Sentence splitting for full CTI reports (inference only).

The paper names the step but not the tool. Paragraphs are separated at blank
lines, whitespace inside a paragraph is collapsed, and NLTK Punkt splits each
paragraph. Nothing is filtered except empty strings.
"""
from __future__ import annotations

import re

import nltk

_PARAGRAPH = re.compile(r"\n\s*\n")
_WHITESPACE = re.compile(r"\s+")


def _ensure_punkt() -> None:
    try:
        nltk.data.find("tokenizers/punkt_tab")
    except LookupError:
        nltk.download("punkt_tab", quiet=True)


def split_sentences(text: str) -> list[str]:
    _ensure_punkt()
    sentences: list[str] = []
    for paragraph in _PARAGRAPH.split(text):
        paragraph = _WHITESPACE.sub(" ", paragraph).strip()
        if paragraph:
            sentences.extend(s.strip() for s in nltk.sent_tokenize(paragraph))
    return [s for s in sentences if s]