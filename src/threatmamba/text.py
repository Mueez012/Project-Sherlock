"""The one sentence splitter: report text -> the ordered sentences that make up the attack's timeline.

Paper, section III-A: one "sentence cutting" step feeds both IOC and TTP extraction; the order of sentences is the
temporal sequence; every temporal node is built from its sentence's TTPs (Eq. 6), and the TTP model is trained on
single sentences (D1). So only real sentences enter the timeline. Headings, table rows, label lines, indicator lists
and other fragments are left out of it. Indicators found in them are still extracted; they belong to no timeline
sentence (attach()), and their context is the line they appear in, the paper's "original text passage".

Input: text with one paragraph per line (blank lines allowed). Pasted text and D2 reports already look like this;
threatmamba.documents turns PDF, DOCX, HTML, Markdown, STIX and TXT files into it, and also says what each line is
(regions): a heading or a table row never becomes a timeline sentence, whatever its words.

1. Paragraphs: every line is a paragraph, except a wrapped sentence, which is joined back:
   - in hard-wrapped text (most lines end near one width, as in TXT exports and text pasted from a PDF), a line that
     reaches that margin continues on the next line, unless the next line is a list item or an indicator list;
   - anywhere, a line of 3 or more words that stops without closing punctuation and is not a heading continues on a
     next line that starts with a plain lowercase word, or with an indicator and then a lowercase word.
   A hyphen at the break is kept ("pro-" + "Russian" -> "pro-Russian", "update-" + "check.net" -> "update-check.net").
2. Sentences: NLTK punkt (nltk pinned in pyproject.toml, its English data stored in data/punkt_tab so splits never
   change under us, plus EXTRA_ABBREVIATIONS) splits each paragraph. Three of punkt's splits are undone: one that
   does not fall on whitespace (it would cut a defanged indicator such as 185.12.45[.]201), one before a lowercase
   letter (no sentence starts that way), and one after an abbreviation that never ends a sentence (NEVER_FINAL;
   punkt would split "i.e. Fancy Bear" because "fancy" is usually lowercase).
3. Kinds: a unit is a "sentence" unless its region says "heading" or "table_row", or it has fewer than 4 words
   ("fragment"), is mostly indicators ("ioc_list"), is a heading line or letter-spaced title ("heading"), does not
   start like a sentence, or is a short piece (under SHORT_WORDS words) that does not end like one ("fragment": web
   headlines, labels, table cells). The first rules are those of the TTP service's own documents
   (services/ttp/ttp_extraction/inference/segment.py); the last two were measured on D2 (they drop scraped headlines
   and related-article links, about 9% of D2's former sentences).

Positions (start, end) index the text exactly as given. A unit's text is that slice with whitespace collapsed, a
hyphen at a joined line break kept without a space, and a leading bullet symbol left out.
datasets/scripts/clean_d2.py writes D2's `sentences` with split_sentences(); the datasets CI job fails if they differ.
services/ioc/ioc_hunter/text.py is a byte-identical copy (IOC Hunter's container cannot import the hub), with the same
data; tests in both places fail if the copies ever differ.
"""

from __future__ import annotations

import re
from bisect import bisect_right
from dataclasses import dataclass
from functools import cache
from pathlib import Path

from nltk.tokenize.punkt import PunktParameters, PunktSentenceTokenizer

PUNKT_DIR = Path(__file__).parent / "data" / "punkt_tab" / "english"

# Added to punkt's English list. "etc." is left out on purpose: it usually ends a sentence.
EXTRA_ABBREVIATIONS = frozenset(
    {"al", "approx", "apr", "dept", "e.g", "est", "fig", "figs", "gov", "i.e", "jul", "jun", "mar", "no", "nos", "rev"}
    | {"ver", "vol"}
)

# Abbreviations that never end a sentence, unlike "Inc." or "U.S.".
NEVER_FINAL = frozenset({"e.g.", "i.e.", "fig.", "figs.", "no.", "nos.", "vs.", "approx.", "al.", "cf.", "ca."})

MIN_WORDS = 4
SHORT_WORDS = 10
MAX_IOC_SHARE = 0.6
MAX_HEADING_WORDS = 12
SENTENCE_END = tuple('.!?:;"”’)]')

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
_WS = re.compile(r"\s+")
_CONTINUES = re.compile(r"[a-z]+[,;:.!?)]*(\s|$)")  # a wrapped sentence continues with a plain lowercase word
_ITEM = re.compile(r"\s*([•▪◦‣●○■□–*-]|\d{1,2}[.)])\s")  # a list item: bullet, dash or "1." / "2)"
_BULLET = re.compile(r"[•▪◦‣●○■□–*-]\s+")
_BREAK_HYPHEN = re.compile(r"(?<=[A-Za-z0-9])-\n(?=\S)")
_STARTS = re.compile(r"""^[•\-*]?\s*["'“‘(\[]?[A-Z0-9]""")  # a sentence starts with a capital, a digit or a quote
_ENDS = re.compile(r"""[.!?]["'”’)\]]*$""")


@dataclass(frozen=True)
class Unit:
    """One piece of the text. Only kind == "sentence" enters the timeline."""

    start: int
    end: int
    text: str
    kind: str  # "sentence", "heading", "table_row", "ioc_list" or "fragment"


def _read_tab(name: str) -> list[list[str]]:
    lines = (PUNKT_DIR / name).read_text(encoding="utf-8").split("\n")
    return [line.split("\t") for line in lines if line.strip()]


def _read_words(name: str) -> set[str]:
    return {w.strip() for w in (PUNKT_DIR / name).read_text(encoding="utf-8").split("\n") if w.strip()}


@cache
def _tokenizer() -> PunktSentenceTokenizer:
    params = PunktParameters()
    params.abbrev_types = _read_words("abbrev_types.txt") | EXTRA_ABBREVIATIONS
    params.collocations = {(a, b) for a, b in _read_tab("collocations.tab")}
    params.sent_starters = _read_words("sent_starters.txt")
    params.ortho_context.update({word: int(flag) for word, flag in _read_tab("ortho_context.tab")})
    return PunktSentenceTokenizer(params)


def ioc_share(text: str) -> float:
    tokens = [t.strip(_PUNCT) for t in text.split()]
    tokens = [t for t in tokens if t]
    return sum(bool(_IOC.match(t)) for t in tokens) / max(len(tokens), 1)


def _is_heading(text: str, first: bool) -> bool:
    words = text.split()
    if not words or len(words) > MAX_HEADING_WORDS or text[-1] in ".!?":
        return False
    long_words = [w for w in words if len(w.strip(_PUNCT)) > 3]
    title_case = bool(long_words) and sum(w.strip(_PUNCT)[:1].isupper() for w in long_words) / len(long_words) >= 0.6
    return first or title_case or text.endswith(":")


def _letter_spaced(text: str) -> bool:
    """A title set in spaced capitals: "E X E C U T I V E  S U M M A R Y"."""
    words = text.split()
    return len(words) >= 4 and sum(len(w) == 1 for w in words) / len(words) >= 0.7


def _kind(text: str, whole_line: bool, first: bool) -> str:
    words = len(text.split())
    if ioc_share(text) > MAX_IOC_SHARE:
        return "ioc_list"
    if words < MIN_WORDS:
        return "fragment"
    if _letter_spaced(text) or (whole_line and _is_heading(text, first)):
        return "heading"
    if not _STARTS.match(text) or (words < SHORT_WORDS and not _ENDS.search(text)):
        return "fragment"
    return "sentence"


def _wrap_width(lengths: list[int]) -> int | None:
    """The margin of hard-wrapped text, or None. Wrapped text never runs past its margin: of 6 or more lines, almost
    none (5% at most) exceed the usual width (40-140 characters) by more than 15%, and 30% or more come close to it.
    D2 reports and pasted web text, where each line is a whole paragraph of any length, do not look like that."""
    if len(lengths) < 6:
        return None
    width = sorted(lengths)[int(0.9 * (len(lengths) - 1))]
    if not 40 <= width <= 140:
        return None
    longer = sum(n > 1.15 * width for n in lengths)
    close = sum(n >= 0.85 * width for n in lengths)
    return width if longer <= 0.05 * len(lengths) and close >= 0.3 * len(lengths) else None


def _paragraphs(text: str) -> list[tuple[int, int]]:
    """(start, end) of each paragraph: one per line, a wrapped sentence joined back (see the module docstring)."""
    lines: list[tuple[int, int] | None] = []
    pos = 0
    for line in text.split("\n"):
        stripped = line.strip()
        if stripped:
            lead = len(line) - len(line.lstrip())
            lines.append((pos + lead, pos + lead + len(stripped)))
        else:
            lines.append(None)  # a blank line always ends a paragraph
        pos += len(line) + 1
    width = _wrap_width([e - s for s, e in (x for x in lines if x)])
    out: list[tuple[int, int]] = []
    joinable = at_margin = False
    for span in lines:
        if span is None:
            joinable = at_margin = False
            continue
        line = text[span[0] : span[1]]
        wrapped = at_margin and not _ITEM.match(line) and ioc_share(line) <= MAX_IOC_SHARE
        if out and (wrapped or (joinable and _continues(line))):
            out[-1] = (out[-1][0], span[1])
        else:
            out.append(span)
        last = text[out[-1][0] : out[-1][1]].split("\n")[-1]
        joinable = len(last.split()) >= 3 and not last.endswith(SENTENCE_END) and not _is_heading(last, first=False)
        at_margin = width is not None and len(last) >= 0.7 * width
    return out


def _continues(line: str) -> bool:
    """Does this line carry on a sentence wrapped from the line before?"""
    if _CONTINUES.match(line):
        return True
    words = line.split()
    return len(words) > 1 and bool(_IOC.match(words[0].strip(_PUNCT))) and bool(_CONTINUES.match(words[1]))


def _sentence_spans(paragraph: str) -> list[tuple[int, int]]:
    """Punkt's sentence spans, with the three kinds of wrong split undone (see the module docstring)."""
    spans: list[tuple[int, int]] = []
    for s, e in _tokenizer().span_tokenize(paragraph):
        if spans:
            prev_end = spans[-1][1]
            last_word = paragraph[spans[-1][0] : prev_end].split()[-1].lower()
            if s == prev_end or paragraph[s].islower() or last_word in NEVER_FINAL:
                spans[-1] = (spans[-1][0], e)
                continue
        spans.append((s, e))
    return spans


def segment(text: str, regions: list[tuple[int, int, str]] | None = None) -> list[Unit]:
    """Every unit of the text in order, with its position and kind. regions, from threatmamba.documents, give each
    line's kind; a unit in a "heading" or "table_row" line takes that kind."""
    starts = [r[0] for r in regions or []]
    units: list[Unit] = []
    for p_start, p_end in _paragraphs(text):
        raw = text[p_start:p_end]
        spans = _sentence_spans(raw.replace("\n", " "))  # same length, so offsets stay aligned
        whole_line = len(spans) == 1 and "\n" not in raw
        for s, e in spans:
            bullet = _BULLET.match(raw, s)
            if bullet and bullet.end() < e:
                s = bullet.end()  # the sentence starts at its words, not at the list marker
            piece = _WS.sub(" ", _BREAK_HYPHEN.sub("-", raw[s:e])).strip()
            if piece:
                kind = _kind(piece, whole_line, first=not units)
                region = regions[bisect_right(starts, p_start + s) - 1] if regions else None
                if region and region[2] in ("heading", "table_row") and region[0] <= p_start + s < region[1]:
                    kind = region[2]
                units.append(Unit(p_start + s, p_start + e, piece, kind))
    return units


def split_sentences(text: str, regions: list[tuple[int, int, str]] | None = None) -> list[str]:
    """The timeline: the text of every unit that is a real sentence, in order."""
    return [u.text for u in segment(text, regions) if u.kind == "sentence"]


def attach(units: list[Unit]) -> list[int | None]:
    """For each unit, its timeline sentence number if it is a sentence, otherwise None. An indicator belongs only to
    the sentences it appears in; one found only in a table row, heading or list line belongs to no sentence."""
    numbers: list[int | None] = []
    n = 0
    for u in units:
        numbers.append(n if u.kind == "sentence" else None)
        n += u.kind == "sentence"
    return numbers
