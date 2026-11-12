"""Does a report give the same timeline whichever way it arrives? Renders real D2 reports as CRLF text, hard-wrapped
TXT, HTML, DOCX and one- and two-column PDFs, reads each back through threatmamba.documents, and compares its
timeline with the report's own (threatmamba.text on the plain text).

    uv run python scripts/check_splitting.py            # 40 reports
    uv run python scripts/check_splitting.py 150 --show 5

"Boundaries wrong" counts sentences that are missing, merged or split; "any difference" also counts spelling inside a
correctly cut sentence (for example a compound rejoined at a PDF line end). For PDFs only sentences the renderer
drew are counted (nearly all of them). The renderer styles headings like body text, which real reports do not, so a
few PDF heading/sentence disagreements are expected.
"""

from __future__ import annotations

import argparse
import html
import io
import json
import random
import re
import textwrap
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def boundary(sentence: str) -> str:
    return re.sub(r"[^0-9a-z]", "", sentence.lower())


def render_pdf(lines: list[str], columns: int = 1) -> bytes:
    import pymupdf

    body = "".join(f"<p>{html.escape(line)}</p>" for line in lines)
    story = pymupdf.Story(html=body, user_css="p {font-family: sans-serif; font-size: 10pt; margin-bottom: 6pt;}")
    buffer = io.BytesIO()
    writer = pymupdf.DocumentWriter(buffer)
    page = pymupdf.paper_rect("a4")
    w, h = page.width, page.height
    rects = (
        [pymupdf.Rect(50, 60, w - 50, h - 60)]
        if columns == 1
        else [pymupdf.Rect(50, 60, w / 2 - 12, h - 60), pymupdf.Rect(w / 2 + 12, 60, w - 50, h - 60)]
    )
    more = True
    while more:
        device = writer.begin_page(page)
        for rect in rects:
            if more:
                more, _ = story.place(rect)
                story.draw(device)
        writer.end_page()
    writer.close()
    return buffer.getvalue()


def render_docx(lines: list[str]) -> bytes:
    import docx

    document = docx.Document()
    for line in lines:
        document.add_paragraph(line)
    buffer = io.BytesIO()
    document.save(buffer)
    return buffer.getvalue()


FORMATS = {
    "crlf.txt": lambda lines: "\r\n".join(lines).encode(),
    "wrapped.txt": lambda lines: "\n\n".join(textwrap.fill(line, 72) for line in lines).encode(),
    "page.html": lambda lines: (
        "<html><body><article>" + "".join(f"<p>{html.escape(x)}</p>" for x in lines) + "</article></body></html>"
    ).encode(),
    "doc.docx": render_docx,
    "one-column.pdf": lambda lines: render_pdf(lines, 1),
    "two-column.pdf": lambda lines: render_pdf(lines, 2),
}


def compare(report_text: str, name: str) -> tuple[int, int, int, list[tuple[str, str]]]:
    """(sentences counted, boundaries wrong, any difference, examples) for one report in one format."""
    from threatmamba.documents import extract_text
    from threatmamba.text import split_sentences

    lines = [line.strip() for line in report_text.split("\n") if line.strip()]
    base = split_sentences("\n".join(lines))
    data = FORMATS[name](lines)
    doc = extract_text(data, "report." + name.rsplit(".", 1)[-1])
    got = split_sentences(doc.text, doc.regions)
    present = base
    if name.endswith(".pdf"):
        import pymupdf

        flags = pymupdf.TEXTFLAGS_TEXT & ~pymupdf.TEXT_PRESERVE_LIGATURES  # "ﬁ" -> "fi", as the reader does
        pdf = pymupdf.open(stream=data, filetype="pdf")
        raw = boundary(" ".join(page.get_text(flags=flags) for page in pdf))
        present = [s for s in base if boundary(s) in raw]
    got_bounds, got_exact = {boundary(g) for g in got}, {" ".join(g.split()) for g in got}
    wrong = [s for s in present if boundary(s) not in got_bounds]
    differ = [s for s in present if " ".join(s.split()) not in got_exact]
    examples = [(s, next((g for g in got if boundary(s)[:30] in boundary(g)), "(none)")) for s in wrong[:1]]
    return len(present), len(wrong), len(differ), examples


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("reports", nargs="?", type=int, default=40)
    parser.add_argument("--show", type=int, default=2, help="examples of wrong boundaries per format")
    parser.add_argument("--seed", type=int, default=11)
    args = parser.parse_args(argv)
    d2 = ROOT / "datasets" / "d2_model_ready"
    rows = [json.loads(line) for part in ("train", "valid", "test") for line in (d2 / f"{part}.jsonl").open()]
    random.seed(args.seed)
    totals: dict[str, list[int]] = defaultdict(lambda: [0, 0, 0])
    examples: dict[str, list[tuple[str, str]]] = defaultdict(list)
    for row in random.sample(rows, args.reports):
        for name in FORMATS:
            counted, wrong, differ, found = compare(row["text"], name)
            t = totals[name]
            t[0], t[1], t[2] = t[0] + counted, t[1] + wrong, t[2] + differ
            examples[name] += found[: max(args.show - len(examples[name]), 0)]
    for name, (counted, wrong, differ) in totals.items():
        print(
            f"{name:15s} boundaries wrong {wrong:4d}/{counted} ({100 * wrong / max(counted, 1):4.1f}%)"
            f" | any difference {differ:4d} ({100 * differ / max(counted, 1):4.1f}%)"
        )
        for want, got in examples[name]:
            print(f"      expected: {want[:110]}\n      got:      {got[:110]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
