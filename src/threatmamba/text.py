"""The one sentence splitter.

It is the exact function that wrote the `sentences` field of every D2 report (datasets/scripts/clean_d2.py), so live
text and dataset reports are numbered the same way. The datasets CI job fails if the two ever disagree.
"""

import re

_BOUNDARY = re.compile(r"(?<=[.!?])\s+(?=[A-Z0-9\"“(])")


def split_sentences(text: str) -> list[str]:
    """Split at line breaks, then after . ! ? followed by whitespace and a capital, digit, quote or bracket."""
    out: list[str] = []
    for line in text.split("\n"):
        out += [s.strip() for s in _BOUNDARY.split(line) if s.strip()]
    return out
