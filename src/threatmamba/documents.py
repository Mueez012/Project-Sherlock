"""Report files -> text with one paragraph per line, plus what each line is (threatmamba.text uses both).

Every line of the text is a region: "text" (a paragraph or list item), "heading", or "table_row" (one table row, its
cells joined with " | "). Headings and table rows never become timeline sentences; indicators in them still count.

PDFs are read with Artifex's layout model (pymupdf4llm + pymupdf-layout, pinned to our PyMuPDF): it labels every
region of a page (text, list item, section header, table, page header, page footer), so page headers and footers are
dropped by label, tables come back as rows of cells, and a paragraph split by a page break is joined again. Two
repairs follow: a hash wrapped inside a table cell is put back together, and a CVE id keeps its hyphens. There is no
OCR: a PDF without a text layer is refused with a clear message. DOCX and HTML tables and headings are typed the same
way from the file's own structure.

Supported: .pdf, .docx, .html/.htm, .md, .txt and STIX 2.1 bundles (.json). For STIX, the ATT&CK ids the bundle
declares are never put in the text (the model must not see the answer); they are returned as `declared_ttps`.
"""

from __future__ import annotations

import io
import json
import re
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path

from threatmamba.text import SENTENCE_END

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
    regions: list[tuple[int, int, str]] = field(default_factory=list)  # (start, end, kind) of every line; see above

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


_CVE = re.compile(r"\bCVE-(\d{4})(\d{4,7})\b")
_HEX = re.compile(r"[0-9a-fA-F]+")
_CELL_HYPHEN = re.compile(r"([A-Za-z])- ([a-z])")
_MARKUP = re.compile(r"\*\*|__|`|<br\s*/?>")


def repair(text: str) -> str:
    """CVE-2021-40444 that lost a hyphen at a line break, in any text."""
    return _CVE.sub(r"CVE-\1-\2", text)


def table_cell(text: str) -> str:
    """One table cell as a single line: a word or hash wrapped inside the cell is joined again."""
    text = _CELL_HYPHEN.sub(r"\1\2", " ".join(text.split()))  # "individ- uals" -> "individuals" (also "b7ad- be8ae4")
    parts = text.split()
    if len(parts) > 1 and all(_HEX.fullmatch(p) for p in parts) and len("".join(parts)) in (32, 40, 64):
        return "".join(parts)  # a SHA-256/SHA-1/MD5 split over the cell's lines
    return text


def build(lines: list[tuple], media_type: str, **extra) -> Document:
    """Typed lines (kind, text[, page]) -> the Document: one line per region, with each region's position and, for
    PDFs, where each page begins."""
    text, regions, page_starts = "", [], []
    for kind, line, *page in lines:
        line = repair(clean_text(line).replace("\n", " "))
        if not line:
            continue
        if text:
            text += "\n"
        while page and len(page_starts) < page[0]:
            page_starts.append(len(text))
        regions.append((len(text), len(text) + len(line), kind))
        text += line
    return Document(text, media_type, regions=regions, page_starts=page_starts, **extra)


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


def _pdf_lines(chunk: dict) -> list[tuple[str, str]]:
    """One page from pymupdf4llm -> typed lines, page header and footer dropped."""
    from bs4 import BeautifulSoup

    out: list[tuple[str, str]] = []
    for box in chunk["page_boxes"]:
        start, end = box["pos"]
        raw, kind = chunk["text"][start:end], box["class"]
        if kind in ("page-header", "page-footer", "picture"):
            continue
        if kind == "table":
            for row in BeautifulSoup(raw, "html.parser").find_all("tr"):
                cells = [table_cell(cell.get_text(" ")) for cell in row.find_all(["td", "th"])]
                if any(cells):
                    out.append(("table_row", " | ".join(c for c in cells if c)))
            continue
        line = _MARKUP.sub(" ", raw)
        line = re.sub(r"^\s*(#+|[-*•])\s+", "", line.strip())  # heading marks and bullets
        line = " ".join(line.split())
        if line:
            out.append(("heading" if kind == "section-header" else "text", line))
    return out


def read_pdf(data: bytes) -> Document:
    import pymupdf
    import pymupdf.layout  # noqa: F401  (switches pymupdf4llm to Artifex's layout model)
    import pymupdf4llm
    from pymupdf4llm.helpers.document_layout import OCRMode

    try:
        pdf = pymupdf.open(stream=data, filetype="pdf")
    except Exception as exc:  # corrupt or encrypted PDFs
        raise DocumentError("unsupported_file", f"the PDF could not be opened ({exc.__class__.__name__})") from exc
    if pdf.needs_pass:
        raise DocumentError("unsupported_file", "the PDF is password protected")
    if sum(len(page.get_text().strip()) for page in pdf) < MIN_CHARS_PER_PDF_PAGE * max(pdf.page_count, 1):
        raise DocumentError("no_text_layer", "the PDF has no text layer (it looks scanned); OCR is not supported")
    chunks = pymupdf4llm.to_markdown(pdf, page_chunks=True, use_ocr=OCRMode.NEVER, table_output="html")
    lines: list[tuple[str, str, int]] = []
    for number, chunk in enumerate(chunks, start=1):
        page = [(kind, line, number) for kind, line in _pdf_lines(chunk)]
        # A paragraph cut by the page break continues on the next page: join it ("thus by-" + "passing ...").
        if lines and page and lines[-1][0] == page[0][0] == "text" and page[0][1][:1].islower():
            kind, prev, prev_page = lines[-1]
            if not prev.endswith(SENTENCE_END):
                joined = prev[:-1] + page[0][1] if re.search(r"[A-Za-z]-$", prev) else f"{prev} {page[0][1]}"
                lines[-1] = (kind, joined, prev_page)
                page = page[1:]
        lines += page
    return build(lines, EXTENSIONS[".pdf"])


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
    media = EXTENSIONS[".md" if markdown else ".txt"]
    return build([("text", line) for line in clean_text(text).split("\n")], media, warnings=warnings)


def read_html(data: bytes) -> Document:
    from bs4 import BeautifulSoup

    raw, warnings = decode_text(data)
    soup = BeautifulSoup(raw, "html.parser")
    for tag in soup(["script", "style", "noscript", "nav", "header", "footer", "aside", "form", "svg", "iframe"]):
        tag.decompose()
    root = soup.find("article") or soup.find("main") or soup.body or soup
    lines: list[tuple[str, str]] = []
    for el in root.find_all([*_BLOCK_TAGS, "tr"]):
        if el.name == "tr":
            cells = [table_cell(c.get_text(" ")) for c in el.find_all(["td", "th"])]
            lines.append(("table_row", " | ".join(c for c in cells if c)))
        elif el.find_parent("tr") is None and el.find([*_BLOCK_TAGS, "tr"]) is None:  # innermost blocks
            kind = "heading" if el.name in ("h1", "h2", "h3", "h4", "h5", "h6") else "text"
            lines.append((kind, el.get_text(" ", strip=True)))
    return build(lines or [("text", root.get_text(" ", strip=True))], EXTENSIONS[".html"], warnings=warnings)


def read_docx(data: bytes) -> Document:
    import docx

    try:
        document = docx.Document(io.BytesIO(data))
    except Exception as exc:
        raise DocumentError("unsupported_file", f"the DOCX could not be opened ({exc.__class__.__name__})") from exc
    lines: list[tuple[str, str]] = []
    for p in document.paragraphs:
        style = (p.style.name if p.style is not None else "").lower()
        lines.append(("heading" if style.startswith(("heading", "title")) else "text", p.text))
    for table in document.tables:
        for row in table.rows:
            lines.append(("table_row", " | ".join(table_cell(cell.text) for cell in row.cells if cell.text.strip())))
    return build(lines, EXTENSIONS[".docx"])


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
    return build([("text", p) for p in paragraphs], EXTENSIONS[".json"], declared_ttps=sorted(declared))


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
