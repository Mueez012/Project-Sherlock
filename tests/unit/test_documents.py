"""Report files -> text with one paragraph per line (threatmamba.documents), and the upload route."""

import io
import json

import docx
import pymupdf
import pytest
from fastapi.testclient import TestClient

from threatmamba.api.main import app
from threatmamba.documents import DocumentError, extract_text, join_wrapped
from threatmamba.text import split_sentences

client = TestClient(app)
BODY = (
    "The actor sent spear-phishing emails to the finance team in March. The attachment dropped a loader that "
    "contacted 185.12.45[.]201 over port 443 and downloaded a second stage."
)


def make_pdf(pages: list[str]) -> bytes:
    pdf = pymupdf.open()
    for text in pages:
        page = pdf.new_page()
        page.insert_textbox(pymupdf.Rect(72, 72, 400, 700), text, fontsize=10)  # narrow box: lines wrap
    return pdf.tobytes()


def test_pdf_wrapped_lines_become_one_paragraph_and_pages_are_known():
    doc = extract_text(make_pdf(["Technical Analysis\n" + BODY, "Second page. " + BODY]), "report.pdf")
    sentences = split_sentences(doc.text)
    assert sentences[0] == BODY.split(". ")[0] + "."  # the wrapped first sentence is whole again
    assert "Technical Analysis" not in sentences  # the heading is not part of the timeline
    assert doc.page_of(doc.text.index("Second page")) == 2
    assert doc.page_of(0) == 1


def test_a_pdf_without_a_text_layer_is_refused():
    pdf = pymupdf.open()
    pdf.new_page()
    with pytest.raises(DocumentError) as e:
        extract_text(pdf.tobytes(), "scan.pdf")
    assert e.value.code == "no_text_layer"


def test_docx_paragraphs_and_tables():
    document = docx.Document()
    document.add_heading("Executive Summary", level=1)
    document.add_paragraph(BODY)
    table = document.add_table(rows=1, cols=2)
    table.rows[0].cells[0].text, table.rows[0].cells[1].text = "evil[.]com", "C2 domain"
    buffer = io.BytesIO()
    document.save(buffer)
    doc = extract_text(buffer.getvalue(), "report.docx")
    assert doc.text.split("\n")[:2] == ["Executive Summary", BODY]
    assert "evil[.]com | C2 domain" in doc.text


def test_html_is_read_per_block_so_links_do_not_break_sentences():
    html = (
        "<html><body><nav>Home | Blog</nav><article><h2>Findings</h2>"
        "<p>The actor used <a href='#'>PowerShell</a> and <b>WMI</b> to move laterally across the network.</p>"
        "<script>var x = 1;</script></article></body></html>"
    )
    doc = extract_text(html.encode(), "post.html")
    assert doc.text == "Findings\nThe actor used PowerShell and WMI to move laterally across the network."


def test_markdown_and_txt():
    md = "# Report\n\nThe actor used **Cobalt Strike** beacons for command and control.\n\n```\ncode here\n```\n"
    assert extract_text(md.encode(), "notes.md").text == (
        "Report\nThe actor used Cobalt Strike beacons for command and control."
    )
    latin1 = "Le groupe a utilisé PowerShell pour télécharger la charge utile.".encode("latin-1")
    doc = extract_text(latin1, "notes.txt")
    assert "utilisé" in doc.text and doc.warnings


def test_stix_bundle_text_without_the_declared_answer():
    bundle = {
        "type": "bundle",
        "objects": [
            {"type": "report", "name": "Campaign X", "description": BODY},
            {
                "type": "attack-pattern",
                "external_references": [{"source_name": "mitre-attack", "external_id": "T1566"}],
            },
        ],
    }
    doc = extract_text(json.dumps(bundle).encode(), "bundle.json")
    assert doc.declared_ttps == ["T1566"]
    assert "T1566" not in doc.text and BODY in doc.text


@pytest.mark.parametrize(
    ("data", "name", "code"), [(b"abc", "x.exe", "unsupported_file"), (b"{}", "x.json", "unsupported_file")]
)
def test_unsupported_files(data, name, code):
    with pytest.raises(DocumentError) as e:
        extract_text(data, name)
    assert e.value.code == "unsupported_file"


def test_join_wrapped_keeps_a_heading_line_on_its_own():
    assert join_wrapped(["Initial Access", "The actor sent emails to the", "finance team in March."]) == [
        "Initial Access",
        "The actor sent emails to the finance team in March.",
    ]


def test_upload_route_returns_timeline_spans_pages_and_reader_notes():
    r = client.post("/api/analyze/file", files={"file": ("report.pdf", make_pdf([BODY, BODY]), "application/pdf")})
    assert r.status_code == 200
    body = r.json()
    assert len(body["sentences"]) == 4
    assert [s["page"] for s in body["spans"]] == [1, 1, 2, 2]
    assert [" ".join(body["text"][s["start"] : s["end"]].split()) for s in body["spans"]] == body["sentences"]
    assert body["iocs"][0]["value"] == "185.12.45.201" and body["iocs"][0]["sentence_indices"] == [1, 3]


def test_upload_route_errors():
    assert (
        client.post("/api/analyze/file", files={"file": ("x.exe", b"MZ", "application/octet-stream")}).status_code
        == 422
    )
    big = b"a" * (20 * 1024 * 1024 + 1)
    assert client.post("/api/analyze/file", files={"file": ("big.txt", big, "text/plain")}).status_code == 413
