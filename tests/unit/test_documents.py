"""Report files -> text with one paragraph per line (threatmamba.documents), and the upload route."""

import io
import json

import docx
import pymupdf
import pytest
from fastapi.testclient import TestClient

from threatmamba.api.main import app
from threatmamba.documents import DocumentError, extract_text, repair, table_cell
from threatmamba.text import attach, segment, split_sentences

client = TestClient(app)
BODY = (
    "The actor sent spear-phishing emails to the finance team in March. The attachment dropped a loader that "
    "contacted 185.12.45[.]201 over port 443 and downloaded a second stage."
)


ROWS = [
    ("NETWORK ARTIFACT", "PHASE", "DETAILS"),
    ("conlfex[.]com", "Initial Compromise", "Doppelganger domain for initial phishing"),
    ("avrobio[.]co", "Initial Compromise", "Doppelganger domain for initial phishing"),
]


def make_pdf(pages: list[str], table: bool = False, heading: str = "") -> bytes:
    """Pages with a running header and footer and an optional bold heading on page 1; optionally a table drawn like
    many CTI reports: cells separated by horizontal rules only, no vertical lines."""
    pdf = pymupdf.open()
    for n, text in enumerate(pages, start=1):
        page = pdf.new_page()
        page.insert_text((72, 60), "ACME CTI | Report 42", fontsize=8)
        page.insert_text((72, 780), f"Page {n}", fontsize=8)
        if heading and n == 1:
            page.insert_text((72, 100), heading, fontsize=14, fontname="hebo")
        page.insert_textbox(pymupdf.Rect(72, 115, 400, 400), text, fontsize=10)  # narrow box: lines wrap
        if table:
            cols, y = [72, 200, 330, 520], 430
            for row in ROWS:
                for i, cell in enumerate(row):
                    page.insert_textbox(pymupdf.Rect(cols[i] + 3, y + 3, cols[i + 1] - 3, y + 30), cell, fontsize=9)
                for i in range(3):
                    page.draw_line((cols[i], y + 32), (cols[i + 1], y + 32), color=(0.85, 0.85, 0.85))
                y += 34
    return pdf.tobytes()


def test_pdf_is_read_by_its_layout_headers_footers_dropped_pages_known():
    pages = [BODY, "Second page of the report. " + BODY]
    doc = extract_text(make_pdf(pages, heading="Technical Analysis"), "report.pdf")
    sentences = split_sentences(doc.text, doc.regions)
    assert sentences[0] == BODY.split(". ")[0] + "."  # the wrapped first sentence is whole again
    assert "Technical Analysis" not in sentences  # the heading is not part of the timeline
    assert "ACME CTI" not in doc.text and "Page 1" not in doc.text  # running header and footer dropped
    assert doc.page_of(doc.text.index("Second page")) == 2
    assert doc.page_of(0) == 1


def test_pdf_tables_are_rows_outside_the_timeline_and_belong_to_no_sentence():
    doc = extract_text(make_pdf([BODY], table=True), "report.pdf")
    rows = [doc.text[s:e] for s, e, kind in doc.regions if kind == "table_row"]
    assert rows == [" | ".join(row) for row in ROWS]
    units = segment(doc.text, doc.regions)
    assert [u.text for u in units if u.kind == "sentence"] == split_sentences(doc.text, doc.regions)
    assert not any("Doppelganger" in s for s in split_sentences(doc.text, doc.regions))
    row = next(i for i, u in enumerate(units) if u.text.startswith("conlfex"))
    assert units[row].kind == "table_row" and attach(units)[row] is None  # no false link to a nearby sentence


def test_a_paragraph_cut_by_a_page_break_is_joined():
    pages = [BODY + " Once hosted, they send a link that is thus by-", "passing any filter. " + BODY]
    doc = extract_text(make_pdf(pages), "r.pdf")
    assert "thus bypassing any filter." in doc.text


def test_cell_and_cve_repairs():
    assert table_cell(["a72538ba00dc95190d69", "19756ffce74f0b3cf60db3", "87c6c9281a0dc892ded8", "02"]) == (
        "a72538ba00dc95190d6919756ffce74f0b3cf60db387c6c9281a0dc892ded802"
    )  # a SHA-256 wrapped inside its cell
    assert table_cell(["77f6cdf03ba70367c93a", "c194604175e2bd1239a", "29bc66da50b5754b7ad-", "be8ae4"]) == (
        "77f6cdf03ba70367c93ac194604175e2bd1239a29bc66da50b5754b7adbe8ae4"
    )  # the PDF even hyphenated the hash
    truncated = [
        "Fe7a64dad14fe24",
        "0aa026e57615fc3a22a",
        "7f5ba1dd55d675b1",
        "d2072f6262a1",
    ]  # 62 characters in the PDF
    assert table_cell(truncated) == " ".join(truncated)  # not a hash, so it is left as it is
    assert table_cell(["SHA 256"]) == "SHA 256"
    assert repair("a 0day exploit (CVE-202140444) for MSHTML") == "a 0day exploit (CVE-2021-40444) for MSHTML"


@pytest.mark.parametrize(
    ("lines", "joined"),
    [
        (["targeted individ-", "uals' addresses"], "targeted individuals' addresses"),  # hyphenation is joined
        (["thus by-", "passing any filter"], "thus bypassing any filter"),
        (["Acquire Infra-", "structure: Domains"], "Acquire Infrastructure: Domains"),
        (["stole credit-", "card data"], "stole credit-card data"),  # compounds keep their hyphen
        (["an attacker-", "controlled system"], "an attacker-controlled system"),
        (["not EMV-", "compliant"], "not EMV-compliant"),
        (["contacted update-", "check[.]net daily"], "contacted update-check[.]net daily"),  # never inside an IOC
        (["exploited CVE-2021-", "40444 in"], "exploited CVE-2021-40444 in"),
        (
            ["see https://example.com/products/", "advanced-threat-defense/"],
            "see https://example.com/products/advanced-threat-defense/",
        ),
        (["(see https://hashcat.net/x/)", "calculates"], "(see https://hashcat.net/x/) calculates"),  # the URL ended
        (["the 32- and", "64-bit loaders"], "the 32- and 64-bit loaders"),
    ],
)
def test_join_lines(lines, joined):
    from threatmamba.documents import join_lines

    assert join_lines(lines) == joined


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
    assert [doc.text[s:e] for s, e, k in doc.regions if k != "text"] == ["Executive Summary", "evil[.]com | C2 domain"]


def test_html_is_read_per_block_so_links_do_not_break_sentences():
    html = (
        "<html><body><nav>Home | Blog</nav><article><h2>Findings</h2>"
        "<p>The actor used <a href='#'>PowerShell</a> and <b>WMI</b> to move laterally across the network.</p>"
        "<script>var x = 1;</script></article></body></html>"
    )
    doc = extract_text(html.encode(), "post.html")
    assert doc.text == "Findings\nThe actor used PowerShell and WMI to move laterally across the network."
    assert [k for *_, k in doc.regions] == ["heading", "text"]


def test_html_table_rows_are_one_line_each():
    html = "<table><tr><th>Indicator</th><th>Role</th></tr><tr><td>evil[.]com</td><td>C2 server</td></tr></table>"
    doc = extract_text(html.encode(), "t.html")
    rows = [(doc.text[s:e], k) for s, e, k in doc.regions]
    assert rows == [("Indicator | Role", "table_row"), ("evil[.]com | C2 server", "table_row")]


def test_markdown_and_txt():
    md = "# Report\n\nThe actor used **Cobalt Strike** beacons for command and control.\n\n```\ncode here\n```\n"
    assert extract_text(md.encode(), "notes.md").text == (
        "Report\n\nThe actor used Cobalt Strike beacons for command and control."  # the paragraph break is kept
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


def test_layout_markup_is_removed_but_names_paths_and_urls_keep_their_underscores():
    from threatmamba.documents import _plain

    assert _plain("<u>https://a.example/c_d_e</u>").strip() == "https://a.example/c_d_e"
    assert _plain("**Exotic Lily** used _spear phishing_ via ~~old~~ `cmd.exe`") == (
        "Exotic Lily used spear phishing via old cmd.exe"
    )
    assert _plain("dropped user_data.dll, __init__.py and C:\\Users\\_tmp_\\a.exe") == (
        "dropped user_data.dll, __init__.py and C:\\Users\\_tmp_\\a.exe"
    )


def test_a_hard_wrapped_txt_file_keeps_its_paragraphs_and_whole_sentences():
    import textwrap

    paragraph = (
        "The Exotic Lily group used spear-phishing emails sent from look-alike domains to reach finance staff at "
        "targets in Western Europe. Windows hosts were then infected with Bumblebee, which contacted 185.12.45[.]201 "
        "for its configuration before PowerShell launched Cobalt Strike on 12 hosts."
    )
    txt = "Initial Access\n\n" + textwrap.fill(paragraph, 72) + "\n\n" + textwrap.fill(paragraph, 72) + "\n"
    doc = extract_text(txt.encode(), "report.txt")
    assert "\n\n" in doc.text  # paragraph breaks survive
    assert split_sentences(doc.text, doc.regions) == split_sentences(paragraph) * 2
