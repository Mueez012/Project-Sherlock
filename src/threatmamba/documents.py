"""Report files -> text with one paragraph per line, the input threatmamba.text expects.

Adapted from the TTP service's reader (services/ttp/ttp_extraction/inference/document.py), with the same libraries
and versions, so reports read the same way everywhere. Differences: every format ends up with one paragraph per line
(PDF lines wrapped inside a text block are joined back into their paragraph, a heading line is kept on its own),
HTML is read per block element so links and bold words do not break a sentence, and there is no OCR: a PDF without a
text layer is refused with a clear message.

Supported: .pdf, .docx, .html/.htm, .md, .txt and STIX 2.1 bundles (.json). For STIX, the ATT&CK ids the bundle
declares are never put in the text (the model must not see the answer); they are returned as `declared_ttps`.
"""

from __future__ import annotations

import io
import json
import re
import unicodedata
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from threatmamba.text import SENTENCE_END, _is_heading

EXTENSIONS = {
    ".pdf": "application/pdf",
    ".txt": "text/plain",
    ".md": "text/markdown",
    ".html": "text/html",
    ".htm": "text/html",
    ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ".json": "application/stix+json",
}
STIX_TEXT_TYPES = ("report", "malware", "intrusion-set", "campaign", "note", "threat-actor", "tool")
MIN_CHARS_PER_PDF_PAGE = 20  # below this on average the PDF has no text layer (it is scanned)
_BLOCK_TAGS = ("p", "li", "h1", "h2", "h3", "h4", "h5", "h6", "td", "th", "pre", "blockquote", "dt", "dd")
_BLOCK_TAGS += ("figcaption", "caption", "div", "section", "article")


class DocumentError(Exception):
    """A file that cannot be turned into text. `code` names the problem."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


@dataclass
class Document:
    text: str
    media_type: str
    page_starts: list[int] = field(default_factory=list)  # PDFs: character offset where each page begins
    warnings: list[str] = field(default_factory=list)
    declared_ttps: list[str] = field(default_factory=list)

    def page_of(self, offset: int) -> int | None:
        """1-based page number of a character offset (None for files without pages)."""
        page = None
        for i, start in enumerate(self.page_starts):
            if start <= offset:
                page = i + 1
        return page


# ------------------------------------------------------------------ cleaning

_QUOTES = str.maketrans(
    {"‘": "'", "’": "'", "‚": "'", "‛": "'", "“": '"', "”": '"', "„": '"', "″": '"', "–": "-", "—": "-", "−": "-"}
    | {"\u00a0": " ", "\u200b": "", "\ufeff": "", "\u00ad": ""}
)
_HYPHEN_BREAK = re.compile(r"(\w)-\n(\w)")
_SPACES = re.compile(r"[ \t\f\v]+")


def clean_text(text: str) -> str:
    """Normalise quotes, dashes and spaces, join words hyphenated across a line break, drop empty lines.
    Line breaks are kept. Defanged indicators such as hxxp:// and example[.]com stay exactly as they are."""
    text = unicodedata.normalize("NFC", text).translate(_QUOTES)
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = _HYPHEN_BREAK.sub(r"\1\2", text)
    return "\n".join(line for line in (_SPACES.sub(" ", line).strip() for line in text.split("\n")) if line)


def join_wrapped(lines: list[str]) -> list[str]:
    """Lines of one PDF text block -> its paragraphs: wrapped lines are joined; a heading line (the block's first
    line, or a line after a finished sentence, that looks like a title) stays on its own."""
    out: list[str] = []
    for line in lines:
        standalone = (not out or out[-1].endswith(SENTENCE_END)) and _is_heading(line, first=False)
        if out and not standalone and not out[-1].endswith(SENTENCE_END) and not _is_heading(out[-1], first=False):
            out[-1] += " " + line
        else:
            out.append(line)
    return out


# ------------------------------------------------------------------ readers


def decode_text(data: bytes) -> tuple[str, list[str]]:
    try:
        return data.decode("utf-8-sig"), []
    except UnicodeDecodeError:
        from charset_normalizer import from_bytes

        best = from_bytes(data).best()
        if best is None:
            raise DocumentError("unsupported_file", "the file is not readable text") from None
        return str(best), [f"text was not UTF-8; decoded as {best.encoding}"]


def read_pdf(data: bytes) -> Document:
    import pymupdf

    try:
        pdf = pymupdf.open(stream=data, filetype="pdf")
    except Exception as exc:  # corrupt or encrypted PDFs
        raise DocumentError("unsupported_file", f"the PDF could not be opened ({exc.__class__.__name__})") from exc
    if pdf.needs_pass:
        raise DocumentError("unsupported_file", "the PDF is password protected")
    pages: list[list[str]] = []
    for page in pdf:
        paragraphs: list[str] = []
        for block in page.get_text("blocks", sort=True):
            if block[6] == 0:  # 0 = a text block
                lines = clean_text(block[4]).split("\n")
                paragraphs += join_wrapped([line for line in lines if line])
        pages.append(paragraphs)
    n_pages, warnings = len(pages), []
    if sum(len(p) for page in pages for p in page) < MIN_CHARS_PER_PDF_PAGE * max(n_pages, 1):
        raise DocumentError("no_text_layer", "the PDF has no text layer (it looks scanned); OCR is not supported")
    if n_pages >= 3:  # repeated page headers and footers: short lines on more than half of the pages
        counts = Counter(p for page in pages for p in set(page) if len(p) < 120)
        repeated = {p for p, c in counts.items() if c > n_pages / 2}
        if repeated:
            pages = [[p for p in page if p not in repeated] for page in pages]
            warnings.append(f"{len(repeated)} repeated page header/footer line(s) removed")
    text, starts = "", []
    for page in pages:
        if text and page:
            text += "\n"
        starts.append(len(text))
        text += "\n".join(page)
    return Document(text, EXTENSIONS[".pdf"], page_starts=starts, warnings=warnings)


def read_plain(data: bytes, markdown: bool = False) -> Document:
    text, warnings = decode_text(data)
    if "\x00" in text:
        raise DocumentError("unsupported_file", "the file looks binary, not text")
    if markdown:
        text = re.sub(r"```.*?```", "\n", text, flags=re.S)  # code blocks are not prose
        text = re.sub(r"^\s{0,3}#{1,6}\s*", "", text, flags=re.M)  # heading markers
        text = re.sub(r"^\s*[-*+]\s+", "", text, flags=re.M)  # bullets
        text = re.sub(r"!?\[([^\]]*)\]\([^)]*\)", r"\1", text)  # links and images -> their label
        text = re.sub(r"(\*\*|__|`)", "", text)
    return Document(clean_text(text), EXTENSIONS[".md" if markdown else ".txt"], warnings=warnings)


def read_html(data: bytes) -> Document:
    from bs4 import BeautifulSoup

    raw, warnings = decode_text(data)
    soup = BeautifulSoup(raw, "html.parser")
    for tag in soup(["script", "style", "noscript", "nav", "header", "footer", "aside", "form", "svg", "iframe"]):
        tag.decompose()
    root = soup.find("article") or soup.find("main") or soup.body or soup
    blocks = [el for el in root.find_all(_BLOCK_TAGS) if el.find(_BLOCK_TAGS) is None]  # innermost blocks
    paragraphs = [el.get_text(" ", strip=True) for el in blocks] or [root.get_text(" ", strip=True)]
    return Document(clean_text("\n".join(paragraphs)), EXTENSIONS[".html"], warnings=warnings)


def read_docx(data: bytes) -> Document:
    import docx

    try:
        document = docx.Document(io.BytesIO(data))
    except Exception as exc:
        raise DocumentError("unsupported_file", f"the DOCX could not be opened ({exc.__class__.__name__})") from exc
    paragraphs = [p.text.replace("\n", " ") for p in document.paragraphs]
    for table in document.tables:
        for row in table.rows:
            paragraphs.append(" | ".join(cell.text.replace("\n", " ") for cell in row.cells))
    return Document(clean_text("\n".join(paragraphs)), EXTENSIONS[".docx"])


def read_stix(data: bytes) -> Document:
    try:
        bundle = json.loads(decode_text(data)[0])
    except (json.JSONDecodeError, DocumentError):
        raise DocumentError("unsupported_file", "the .json file is not valid JSON") from None
    if not isinstance(bundle, dict) or bundle.get("type") != "bundle":
        raise DocumentError("unsupported_file", "the .json file is not a STIX 2.1 bundle")
    paragraphs, declared = [], set()
    for obj in bundle.get("objects", []):
        kind = obj.get("type")
        if kind in STIX_TEXT_TYPES:
            for key in ("name", "description", "abstract", "content"):
                value = obj.get(key)
                if isinstance(value, str) and value.strip():
                    paragraphs.append(value)
        elif kind == "attack-pattern":
            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
                    declared.add(ref["external_id"])
    return Document(clean_text("\n".join(paragraphs)), EXTENSIONS[".json"], declared_ttps=sorted(declared))


def extract_text(data: bytes, filename: str) -> Document:
    """Read one uploaded file by its extension. Raises DocumentError."""
    ext = Path(filename).suffix.lower()
    if ext == ".pdf":
        doc = read_pdf(data)
    elif ext in (".txt", ".md"):
        doc = read_plain(data, markdown=ext == ".md")
    elif ext in (".html", ".htm"):
        doc = read_html(data)
    elif ext == ".docx":
        doc = read_docx(data)
    elif ext == ".json":
        doc = read_stix(data)
    else:
        supported = ", ".join(sorted(EXTENSIONS))
        raise DocumentError("unsupported_file", f"unsupported file type {ext or '(none)'!r}; supported: {supported}")
    if not doc.text.strip():
        raise DocumentError("no_text", "no readable text was found in the file")
    return doc
