import re

from ttp_extraction.inference.document import Document
from ttp_extraction.inference.segment import ioc_share, split_with_offsets
from ttp_extraction.preprocessing.sentences import split_sentences

TEXT = ("The actor sent spearphishing emails.   Then a dropper\ninstalled a backdoor on the host.\n\n"
        "The backdoor used HTTP for command and control. Data was compressed before exfiltration.\n\n"
        "IOCs: 44d88612fea8a8f36de82e1278abb02f 10.1.2.3 hxxp://evil[.]com/x.exe\n\n"
        "See above.")


def test_text_matches_phase8_splitter():
    assert [s.text for s in split_with_offsets(TEXT)] == split_sentences(TEXT)


def test_offsets_slice_back_to_the_sentence():
    for s in split_with_offsets(TEXT):
        assert re.sub(r"\s+", " ", TEXT[s.char_start : s.char_end]) == s.text
        assert TEXT[s.char_start] == s.text[0] and TEXT[s.char_end - 1] == s.text[-1]


def test_ioc_lines_and_short_sentences_are_skipped():
    sentences = split_with_offsets(TEXT)
    reasons = {s.text: s.skip_reason for s in sentences}
    assert reasons["See above."] == "short"
    ioc = next(s for s in sentences if "44d88612" in s.text)
    assert ioc.skip_reason == "ioc_list"
    assert sum(s.skip_reason is None for s in sentences) == 4
    assert all(s.skip_reason != "heading" for s in sentences)


def test_ioc_share_counts_defanged_indicators():
    assert ioc_share("1.2.3.4 evil[.]com hxxps://bad[.]org/a 0123456789abcdef0123456789abcdef") == 1.0
    assert ioc_share("The actor used PowerShell to run commands") == 0.0


def test_page_mapping():
    doc = Document("Page one sentence is here.\n\nPage two sentence is here.", "application/pdf",
                   pages=2, page_starts=[0, 28])
    sentences = split_with_offsets(doc.text, doc.page_of)
    assert [s.page for s in sentences] == [1, 2]


def test_headings_are_skipped_but_bullets_are_kept():
    text = ("Operation Test: synthetic report (not real)\n\nThe actor used PowerShell to run commands.\n\n"
            "uses PowerShell to download payloads\n\nTechnical Analysis of the Loader\n\n"
            "Persistence mechanisms used by the group:")
    reasons = {s.text: s.skip_reason for s in split_with_offsets(text)}
    assert reasons["Operation Test: synthetic report (not real)"] == "heading"      # first line
    assert reasons["Technical Analysis of the Loader"] == "heading"                # Title Case
    assert reasons["Persistence mechanisms used by the group:"] == "heading"       # ends with ':'
    assert reasons["uses PowerShell to download payloads"] is None                 # bullet: kept
    assert reasons["The actor used PowerShell to run commands."] is None
