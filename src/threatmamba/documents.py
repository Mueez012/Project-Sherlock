"""Report files -> text with one paragraph per line, plus what each line is (threatmamba.text uses both).

Every line of the text is a region: "text" (a paragraph), "list_item", "heading", or "table_row" (one table row, its
cells joined with " | "). threatmamba.text decides from these which pieces are timeline sentences.

Every format keeps the report's own characters (curly quotes, dashes), exactly as pasted text and D2 do, so a report
gives the same sentences whichever way it arrives; only invisible characters (soft hyphen, zero-width space, byte
order mark) are removed and no-break spaces become spaces.

PDFs: Artifex's layout model (pymupdf4llm + pymupdf-layout, pinned to our PyMuPDF) labels every region of a page
(text, list item, section header, table, page header, page footer); headers and footers are dropped by label and
tables come back as cells. The text of each region is assembled here from the PDF's own lines, with one rule for a
hyphen at a line end (join_lines): typesetting hyphenation of a word is joined ("individ-" + "uals"), a compound
keeps its hyphen ("credit-" + "card"), and so does anything that is not a plain word (update-check[.]net,
CVE-2021-40444). A paragraph split by a page break is joined again, and a hash wrapped inside a table cell is put
back together. There is no OCR: a PDF without a text layer is refused with a clear message. DOCX and HTML headings,
list items and tables are typed from the file's own structure.

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

from threatmamba.text import PUNKT_DIR, SENTENCE_END

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

_INVISIBLE = str.maketrans({"\u00a0": " ", "\u200b": "", "\ufeff": "", "\u00ad": "", "\u2060": ""})
_SPACES = re.compile(r"[ \t\f\v]+")


def clean_text(text: str) -> str:
    """Remove invisible characters, collapse spaces, drop empty lines. Quotes, dashes, line breaks and a hyphen at a
    line break are kept (deleting it would turn update-check.net into a different indicator). Defanged indicators such
    as hxxp:// and example[.]com stay exactly as they are."""
    text = unicodedata.normalize("NFC", text).translate(_INVISIBLE)
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    return "\n".join(line for line in (_SPACES.sub(" ", line).strip() for line in text.split("\n")) if line)


_CVE = re.compile(r"\bCVE-(\d{4})(\d{4,7})\b")
_HEX = re.compile(r"[0-9a-fA-F]+")
# Inline styles the layout converter writes: <sup>/<u>/<mark>/<br> tags, **bold**, _italic_, ~~strike~~, `mono`.
# The words inside stay. Italics open after a space or bracket and close before a space or punctuation, so
# underscores in names, paths and URLs (user_data.dll, __init__.py, C:\\Users\\_tmp_\\a.exe) are kept.
_TAGS = re.compile(r"</?(?:sup|sub|u|mark|b|i|s|em|strong|span|br)\b[^>]*>", re.I)
_PAIRED = re.compile(r"\*\*(.+?)\*\*|~~(.+?)~~|`([^`]+)`|(?<![^\s(])_(?=[^\s_])(.+?)(?<=[^\s_])_(?![^\s.,;:!?)])")


def _plain(markdown: str) -> str:
    text = _TAGS.sub(" ", markdown)
    for _ in range(3):  # nested styles (bold italic)
        text = _PAIRED.sub(lambda m: next(g for g in m.groups() if g is not None), text)
    return text.replace("**", "")


def repair(text: str) -> str:
    """CVE-2021-40444 that lost a hyphen at a line break, in any text."""
    return _CVE.sub(r"CVE-\1-\2", text)


def _words() -> set[str]:
    """English word types from punkt's stored data (about 20,000), to tell hyphenation from compounds."""
    global _WORDS
    if _WORDS is None:
        lines = (PUNKT_DIR / "ortho_context.tab").read_text(encoding="utf-8").split("\n")
        _WORDS = {line.split("\t")[0] for line in lines if line}
    return _WORDS


_WORDS: set[str] | None = None
_ENDINGS = ("ing", "ed", "es", "s", "ly", "ion", "ions", "ment", "ments", "er", "ers", "al", "able")


def _is_word(token: str, words: set[str]) -> bool:
    """A known English word, allowing a common ending ("bypassing" -> bypass, "attacker" -> attack)."""
    return token in words or any(token.endswith(x) and token[: -len(x)] in words for x in _ENDINGS)


_LEFT_WORD = re.compile(r"([A-Za-z]+)-$")
_ACRONYM = re.compile(r"\b[A-Z]{2,}-$")
_URL_TAIL = re.compile(r"(?:https?://|hxxps?://|www\.)\S*[^\s).,;:!?\]'\"”’]$")  # an unfinished URL
_PAGE_NUMBER = re.compile(r"^(page\s*)?\d+(\s*(of|/)\s*\d+)?$|^[-–]\s*\d+\s*[-–]$", re.I)
_RIGHT_WORD = re.compile(r"([a-z]+)[,.;:!?)\]\"'”’]*$")


def join_lines(lines: list[str]) -> str:
    """The lines of one typeset region (a PDF paragraph, a table cell) as one line. A hyphen at a line end before a
    plain lowercase word is typesetting hyphenation, and is removed, when the left half is not a word (the line split
    a word: "individ-" + "uals", "Infra-" + "structure") or the joined form is one ("by-" + "passing"). Otherwise it
    is a compound and is kept ("credit-" + "card", "attacker-" + "controlled"), and so is anything after an acronym
    or that is not a plain word (EMV-compliant, update-check[.]net, CVE-2021-40444, "pro-" + "Russian")."""
    out = ""
    for line in (" ".join(raw.split()) for raw in lines):
        if not line:
            continue
        if not out:
            out = line
        elif out.endswith("/") or (_URL_TAIL.search(out) and not line[0].isupper()):
            out += line  # "advertising/" + "marketing", a URL wrapped at the line end
        elif out.endswith("-"):
            first = line.split()[0]
            left, right = _LEFT_WORD.search(out), _RIGHT_WORD.match(first)
            words = _words()
            if not first[0].isalnum() or first in ("and", "or", "to") or out.endswith(("--", " -")):
                out += " " + line  # "Smartphones- “Jailbreaking”", "32- and 64-bit", a dash "--" at the line end
            elif left and right and not _ACRONYM.search(out):
                a, b = left.group(1).lower(), right.group(1)
                hyphenated = _is_word(a + b, words) or not _is_word(a, words)
                out = out[:-1] + line if hyphenated else out + line
            else:
                out += line  # a compound or not a plain word: the hyphen stays
        else:
            out += " " + line
    return out


def table_cell(lines: list[str]) -> str:
    """One table cell as a single line (join_lines); a hash wrapped over the cell's lines is put back together."""
    text = join_lines(lines)
    flat = text.replace(" ", "").replace("-", "")
    if flat != text and _HEX.fullmatch(flat) and len(flat) in (32, 40, 64):
        return flat  # a SHA-256/SHA-1/MD5 split over the cell's lines (even with a hyphen inserted)
    return text


def build(lines: list[tuple], media_type: str, **extra) -> Document:
    """Typed lines (kind, text[, page]) -> the Document: one line per region, with each region's position and, for
    PDFs, where each page begins. A ("blank", "") line keeps a paragraph break as an empty line."""
    text, regions, page_starts = "", [], []
    blank = False
    for kind, line, *page in lines:
        if kind == "blank":
            blank = bool(text)
            continue
        line = repair(clean_text(line).replace("\n", " "))
        if not line:
            continue
        if text:
            text += "\n\n" if blank else "\n"
        blank = False
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


def _cells(row) -> list[str]:
    """The cells of one HTML table row, each as one line."""
    out = []
    for cell in row.find_all(["td", "th"]):
        lines = [_plain(line) for line in cell.get_text("\n").split("\n")]
        out.append(table_cell(lines))
    return out


_PDF_KINDS = {"section-header": "heading", "list-item": "list_item"}
_FLOW_SLACK = 24  # points


def _same_column(a, b) -> bool:
    overlap = min(a["rect"].x1, b["rect"].x1) - max(a["rect"].x0, b["rect"].x0)
    return overlap > 0.3 * min(a["rect"].width, b["rect"].width)


def _ends_column(box, page: list[dict]) -> bool:
    """Nothing on the page sits below this region in its column."""
    return not any(o is not box and _same_column(o, box) and o["rect"].y0 >= box["rect"].y1 - 2 for o in page)


def _reading_order(boxes: list[dict]) -> list[dict]:
    """Regions in reading order, column by column. A full-width region (a heading across columns, a table) closes a
    band; inside a band, each column is read top to bottom, left column first. The layout model's own order can
    interleave columns, which would splice sentences from different columns together."""
    if len(boxes) < 2:
        return boxes
    width = max(b["rect"].x1 for b in boxes) - min(b["rect"].x0 for b in boxes)
    out, band = [], []

    def flush():
        columns: list[list[dict]] = []
        for b in sorted(band, key=lambda b: b["rect"].x0):
            column = next((c for c in columns if _same_column(c[0], b)), None)
            if column is None:
                columns.append([b])
            else:
                column.append(b)
        for column in sorted(columns, key=lambda c: min(b["rect"].x0 for b in c)):
            out.extend(sorted(column, key=lambda b: b["rect"].y0))  # stable: table rows keep their order
        band.clear()

    for b in sorted(boxes, key=lambda b: b["rect"].y0):
        if b["rect"].width >= 0.6 * width:
            flush()
            out.append(b)
        else:
            band.append(b)
    flush()
    return out


def _starts_column(box, page: list[dict]) -> bool:
    """Nothing on the page sits above this region in its column."""
    return not any(o is not box and _same_column(o, box) and o["rect"].y1 <= box["rect"].y0 + 2 for o in page)


def _pdf_boxes(chunk: dict, page) -> list[dict]:
    """One page -> its regions in reading order: kind, text, bounding box. Regions come from the layout model;
    the text of non-table regions from the PDF's own lines (join_lines), tables from the model's cells."""
    import pymupdf
    from bs4 import BeautifulSoup

    flags = pymupdf.TEXTFLAGS_DICT & ~pymupdf.TEXT_PRESERVE_LIGATURES & ~pymupdf.TEXT_DEHYPHENATE  # "ﬁ" -> "fi"
    out = []
    for box in chunk["page_boxes"]:
        kind, rect = box["class"], pymupdf.Rect(box["bbox"])
        if kind == "picture":
            continue
        if kind == "table":
            start, end = box["pos"]
            for row in BeautifulSoup(chunk["text"][start:end], "html.parser").find_all("tr"):
                cells = [c for c in _cells(row) if c]
                if cells:
                    out.append({"kind": "table_row", "text": " | ".join(cells), "rect": rect})
            continue
        clip = page.get_text("dict", clip=rect, flags=flags)
        lines = [
            "".join(span["text"] for span in line["spans"])
            for block in clip["blocks"]
            if block["type"] == 0
            for line in block["lines"]
        ]
        text = join_lines(lines)
        if text:
            out.append(
                {
                    "kind": kind if kind in ("page-header", "page-footer") else _PDF_KINDS.get(kind, "text"),
                    "text": text,
                    "rect": rect,
                }
            )
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
    pages = [_reading_order(_pdf_boxes(chunk, pdf[n])) for n, chunk in enumerate(chunks)]

    # A page header or footer is dropped only if it is one: its text repeats on 2+ pages, or it is a page number.
    # The layout model can label a short last paragraph of a page "footer"; that text is kept.
    def key(text: str) -> str:
        return re.sub(r"\d+", "#", text.lower())

    seen = Counter(
        key(b["text"])
        for page in pages
        for b in {key(x["text"]): x for x in page}.values()
        if b["kind"] in ("page-header", "page-footer")
    )
    for page in pages:
        for b in page:
            if b["kind"] in ("page-header", "page-footer"):
                repeated = seen[key(b["text"])] >= 2 or _PAGE_NUMBER.match(b["text"].strip())
                b["kind"] = "drop" if repeated else "text"

    lines: list[tuple[str, str, int]] = []
    previous = None  # the last text-like region kept, if it ends its column: (page number, box)
    for number, page in enumerate(pages, start=1):
        kept = [b for b in page if b["kind"] != "drop"]
        for b in kept:
            text, kind = b["text"], b["kind"]
            # Text flowing from the bottom of one column (or page) to the top of the next is one paragraph: the
            # earlier region ends its column mid-sentence and this one starts a column, further right or on a later
            # page. The position decides, not the capital letter ("... by SC" + "Magazine, named ...").
            if previous and lines and kind == lines[-1][0] and not lines[-1][1].endswith(SENTENCE_END):
                prev_page, prev_box = previous
                moved_on = prev_page < number or b["rect"].x0 > prev_box["rect"].x0 + _FLOW_SLACK
                if moved_on and _starts_column(b, kept):
                    lines[-1] = (kind, join_lines([lines[-1][1], text]), lines[-1][2])
                    previous = (number, b) if _ends_column(b, kept) else None
                    continue
            lines.append((kind, text, number))
            text_like = kind in ("text", "list_item")
            previous = (number, b) if text_like and _ends_column(b, kept) else None
    return build(lines, EXTENSIONS[".pdf"])


def read_plain(data: bytes, markdown: bool = False) -> Document:
    text, warnings = decode_text(data)
    if "\x00" in text:
        raise DocumentError("unsupported_file", "the file looks binary, not text")
    if markdown:
        text = re.sub(r"```.*?```", "\n", text, flags=re.S)  # code blocks are not prose
        text = re.sub(r"^\s{0,3}#{1,6}\s*", "", text, flags=re.M)  # heading markers
        text = re.sub(r"^\s*[-*+]\s+", "• ", text, flags=re.M)  # bullets stay list items
        text = re.sub(r"!?\[([^\]]*)\]\([^)]*\)", r"\1", text)  # links and images -> their label
        text = re.sub(r"(\*\*|__|`)", "", text)
    media = EXTENSIONS[".md" if markdown else ".txt"]
    lines = [("text", line) if line.strip() else ("blank", "") for line in text.replace("\r\n", "\n").split("\n")]
    return build(lines, media, warnings=warnings)


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
            cells = [table_cell([c.get_text(" ")]) for c in el.find_all(["td", "th"])]
            lines.append(("table_row", " | ".join(c for c in cells if c)))
        elif el.find_parent("tr") is None and el.find([*_BLOCK_TAGS, "tr"]) is None:  # innermost blocks
            heading = el.name in ("h1", "h2", "h3", "h4", "h5", "h6")
            kind = "list_item" if el.name == "li" else "heading" if heading else "text"
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
        kind = "heading" if style.startswith(("heading", "title")) else "list_item" if "list" in style else "text"
        lines.append((kind, p.text))
    for table in document.tables:
        for row in table.rows:
            cells = [table_cell(cell.text.split("\n")) for cell in row.cells if cell.text.strip()]
            lines.append(("table_row", " | ".join(cells)))
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
