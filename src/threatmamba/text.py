"""Sentence splitting shared by every module so sentence_index means the same thing everywhere."""

import re

_SPLIT = re.compile(r"(?<=[.!?])\s+|\n+")


def split_sentences(text: str, min_chars: int = 3) -> list[str]:
    return [s.strip() for s in _SPLIT.split(text) if len(s.strip()) >= min_chars]
