"""Clean text -> sentences with character offsets (for highlighting in the UI).

The sentence TEXT is exactly what preprocessing/sentences.split_sentences
gives (paragraphs at blank lines, whitespace collapsed, NLTK Punkt), so the
model sees the same input as in the Phase 8 extractor. In addition every
sentence keeps `char_start`/`char_end` into the original text.

Sentences that are noise for a model trained on ATT&CK procedure sentences are
skipped (and counted): fewer than 4 words, more than 60% IOC tokens
(hashes, IP addresses, URLs, file paths), or a heading/title line.

A heading is a sentence that fills a whole line of the text (a line break or
the start/end of the text on both sides), has at most 12 words and no closing
. ! or ?, AND is either the first line of the document, mostly Title Case, or
ends with ':'. PDFs often glue a section title to the paragraph before it with a
single line break, so this is checked per line, not per paragraph. The extra condition keeps bullet points such as
"uses PowerShell to download payloads", which are real procedure text.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from nltk.tokenize.punkt import PunktTokenizer

from ttp_extraction.preprocessing.sentences import _ensure_punkt

_PARAGRAPH = re.compile(r"\n\s*\n")
_WORD = re.compile(r"\S+")
MIN_WORDS = 4
MAX_IOC_SHARE = 0.6
MAX_HEADING_WORDS = 12

_IOC = re.compile(
    r"""^(
        [a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64}              # md5 / sha1 / sha256
      | \d{1,3}(\[?\.\]?\d{1,3}){3}(:\d+)?(/\d+)?           # IPv4 (also defanged 1[.]2[.]3[.]4)
      | [0-9a-f:]{2,}:[0-9a-f:]{2,}                         # IPv6
      | (h(xx|tt)ps?|fxp|ftp)(\[?:\]?)//\S+                  # URLs (also defanged)
      | [\w-]+(\[?\.\]?[\w-]+)*\[\.\][a-z]{2,}\S*           # defanged domains
      | [\w.-]+\.(com|net|org|ru|cn|io|info|biz|xyz|top|exe|dll|bat|ps1|vbs|js|zip|rar)\S*
      | [a-z]:\\\S*|/(usr|etc|tmp|var|bin|home)/\S*         # file paths
      | CVE-\d{4}-\d+
    )$""",
    re.I | re.X,
)
_PUNCT = ".,;:()[]{}<>\"'"

_tokenizer: PunktTokenizer | None = None


@dataclass
class Sentence:
    index: int
    text: str
    char_start: int
    char_end: int
    page: int | None = None
    skip_reason: str | None = None     # None = sent to the model


def _punkt() -> PunktTokenizer:
    global _tokenizer
    if _tokenizer is None:
        _ensure_punkt()
        _tokenizer = PunktTokenizer("english")
    return _tokenizer


def ioc_share(sentence: str) -> float:
    tokens = [t.strip(_PUNCT) for t in sentence.split()]
    tokens = [t for t in tokens if t]
    return sum(bool(_IOC.match(t)) for t in tokens) / max(len(tokens), 1)


def skip_reason(sentence: str) -> str | None:
    if ioc_share(sentence) > MAX_IOC_SHARE:
        return "ioc_list"
    if len(sentence.split()) < MIN_WORDS:
        return "short"
    return None


def is_heading(paragraph: str, first: bool) -> bool:
    words = paragraph.split()
    if not words or len(words) > MAX_HEADING_WORDS or paragraph.rstrip()[-1] in ".!?":
        return False
    long_words = [w for w in words if len(w.strip(_PUNCT)) > 3]
    title_case = bool(long_words) and sum(w.strip(_PUNCT)[:1].isupper() for w in long_words) / len(long_words) >= 0.6
    return first or title_case or paragraph.rstrip().endswith(":")


def split_with_offsets(text: str, page_of=None) -> list[Sentence]:
    """All sentences of `text` with offsets; `page_of(offset)` gives the page."""
    sentences: list[Sentence] = []
    start = 0
    for match in [*_PARAGRAPH.finditer(text), None]:
        end = match.start() if match else len(text)
        raw = text[start:end]
        # Collapse whitespace, remembering where each kept character came from.
        collapsed, origin = [], []
        for m in _WORD.finditer(raw):
            if collapsed:
                collapsed.append(" ")
                origin.append(start + m.start() - 1)
            collapsed.extend(m.group())
            origin.extend(range(start + m.start(), start + m.end()))
        paragraph = "".join(collapsed)
        if paragraph:
            for s, e in _punkt().span_tokenize(paragraph):
                piece = paragraph[s:e]
                lead = len(piece) - len(piece.lstrip())
                piece = piece.strip()
                if not piece:
                    continue
                s += lead
                e = s + len(piece)
                char_start, char_end = origin[s], origin[e - 1] + 1
                whole_line = ((char_start == 0 or text[char_start - 1] == "\n")
                              and (char_end == len(text) or text[char_end] == "\n"))
                heading = whole_line and is_heading(piece, first=not sentences)
                reason = skip_reason(piece) or ("heading" if heading else None)
                sentences.append(Sentence(
                    index=len(sentences), text=piece, char_start=char_start, char_end=char_end,
                    page=page_of(char_start) if page_of else None, skip_reason=reason,
                ))
        if match:
            start = match.end()
    return sentences
