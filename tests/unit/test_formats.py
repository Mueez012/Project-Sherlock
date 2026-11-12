"""The same real report gives the same timeline whichever way it arrives (scripts/check_splitting.py)."""

import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("check_splitting", ROOT / "scripts" / "check_splitting.py")
check = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check)

REPORTS = [json.loads(line) for line in (ROOT / "datasets" / "d2_model_ready" / "test.jsonl").open()][:8]


@pytest.mark.parametrize("name", ["crlf.txt", "page.html", "doc.docx"])
def test_text_html_and_docx_give_exactly_the_same_timeline(name):
    for report in REPORTS:
        counted, wrong, differ, _ = check.compare(report["text"], name)
        assert (wrong, differ) == (0, 0), (report["report_id"], name)


def test_hard_wrapped_text_keeps_almost_every_boundary():
    counted = wrong = 0
    for report in REPORTS:
        c, w, _, _ = check.compare(report["text"], "wrapped.txt")
        counted, wrong = counted + c, wrong + w
    assert wrong <= 0.02 * counted


@pytest.mark.parametrize("name", ["one-column.pdf", "two-column.pdf"])
def test_pdfs_keep_almost_every_boundary(name):
    counted = wrong = 0
    for report in REPORTS[:3]:
        c, w, _, _ = check.compare(report["text"], name)
        counted, wrong = counted + c, wrong + w
    assert counted > 0 and wrong <= 0.05 * counted
