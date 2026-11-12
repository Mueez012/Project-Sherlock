import hashlib
from pathlib import Path

import pytest

from threatmamba.contracts import IOCType
from threatmamba.ioc import RegexIOCExtractor
from threatmamba.text import PUNKT_DIR, attach, segment, split_sentences
from threatmamba.ttp import KeywordTTPExtractor

REPORT = """Operation Example: Technical Analysis
The U.S. Treasury and Fig. 3 show the actor used e.g. PowerShell to fetch hxxp://evil[.]com/a.ps1 today. The loader
contacted 185.12.45[.]201 over port 443.
Indicators:
evil[.]com
185.12.45[.]201
d41d8cd98f00b204e9800998ecf8427e"""


def test_only_real_sentences_enter_the_timeline():
    assert split_sentences(REPORT) == [
        "The U.S. Treasury and Fig. 3 show the actor used e.g. PowerShell to fetch hxxp://evil[.]com/a.ps1 today.",
        "The loader contacted 185.12.45[.]201 over port 443.",
    ]
    assert [u.kind for u in segment(REPORT)] == ["heading", "sentence", "sentence", "fragment"] + ["ioc_list"] * 3


def test_units_keep_their_exact_positions_and_never_cut_a_word():
    for u in segment(REPORT):
        assert REPORT[u.start : u.end].split() == u.text.split()
        assert u.start == 0 or REPORT[u.start - 1].isspace()
        assert u.end == len(REPORT) or REPORT[u.end].isspace()


def test_only_sentences_are_timeline_steps_other_lines_belong_to_none():
    # heading, two sentences, then a label and an indicator list: those belong to no timeline sentence
    assert attach(segment(REPORT)) == [None, 0, 1, None, None, None, None]
    assert attach(segment("Indicators:\nevil[.]com")) == [None, None]


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("The actor ran malware on the host. Then it left the network.", 2),  # an ordinary full stop
        ("Version 2.0 of the tool shipped. then it broke completely.", 1),  # a lowercase word does not start one
        ("The group, e.g. APT28, used it. The group, i.e. Fancy Bear, left.", 2),  # e.g. / i.e. do not end one
        ("See Fig. 4 for the full chain. No. 5 was the last stage here.", 2),
        ("E X E C U T I V E  S U M M A R Y", 0),  # a letter-spaced title
        ("Hackers use leaked ransomware to attack banks", 0),  # a short headline without sentence punctuation
        ("We assess that the group has ties with pro-Russian\ngroups.", 1),  # a wrap that ends a sentence
        ("victims clicking on malicious files contained within ISO files.", 0),  # does not start like a sentence
        ("The actor came back in May.\nThe attacker wrote the payload\nin Go and packed it with UPX.", 2),  # joined
        ("The actor came back in May.\nThe attacker wrote the payload\nAPT28 then used it on the network.", 2),
    ],
)
def test_sentence_rules(text, expected):
    assert len(split_sentences(text)) == expected


def test_the_stored_punkt_data_is_unchanged():
    """The splitter's data is part of the dataset contract: if it changed, D2's sentences would no longer match."""
    expected = {
        "abbrev_types.txt": "92a3e070f43d9b4c5534758ca40ad7343b04e7e29bfe0c2eb658a39445a4f779",
        "collocations.tab": "8e2da1225e4dd2cc9dba261ee231ccb134859e21b46006e7f472c5ee269af0cf",
        "ortho_context.tab": "4bbcca25ed3d3f06c02402abf8419b9f033b8adc06e7b482eca4e45f81a5dc4c",
        "sent_starters.txt": "f3f8535483e1dba487241b764945168123bca3209a9645e59acd1225dc76edac",
    }
    assert {f: hashlib.sha256((PUNKT_DIR / f).read_bytes()).hexdigest() for f in expected} == expected


def test_ioc_hunter_cuts_with_an_identical_copy():
    ioc = Path(__file__).resolve().parents[2] / "services" / "ioc" / "ioc_hunter"
    assert (ioc / "text.py").read_bytes() == (PUNKT_DIR.parents[2] / "text.py").read_bytes()
    for f in PUNKT_DIR.iterdir():
        assert (ioc / "data" / "punkt_tab" / "english" / f.name).read_bytes() == f.read_bytes()


def test_ioc_extractor_refangs_and_types():
    sents = ["C2 at 185.12.45[.]201 and hxxp://evil[.]info/a.ps1 plus CVE-2021-44228."]
    iocs = {(i.type, i.value) for i in RegexIOCExtractor().extract(sents)}
    assert (IOCType.ipv4, "185.12.45.201") in iocs
    assert (IOCType.url, "http://evil.info/a.ps1") in iocs
    assert (IOCType.cve, "CVE-2021-44228") in iocs


def test_ioc_extractor_prefers_longest_hash_and_keeps_every_sentence():
    h = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
    iocs = RegexIOCExtractor().extract([f"hash {h}", "nothing here", f"again {h}"])
    assert [(i.type, i.sentence_indices) for i in iocs] == [(IOCType.sha256, [0, 2])]
    assert iocs[0].context == [f"hash {h}", f"again {h}"]
    assert iocs[0].source == "regex stub"


def test_ttp_keyword_extractor_maps_sentences():
    hits = KeywordTTPExtractor().predict(["A spear-phishing email arrived.", "Nothing here.", "PowerShell ran."])
    assert {(h.technique_id, h.sentence_index) for h in hits} == {("T1566", 0), ("T1059", 2)}
    assert all(0 <= h.score <= 1 for h in hits)


WRAPPED_PARAGRAPH = (
    "The Exotic Lily group used spear-phishing emails sent from look-alike domains such as update-check[.]net to reach "
    "finance staff at APT28-style targets in Western Europe. Windows hosts were then infected with Bumblebee, which "
    "contacted 185.12.45[.]201 for its configuration and pro-Russian infrastructure for later stages of the attack. "
    "Microsoft Defender flagged the loader only after 2 days, when PowerShell launched Cobalt Strike on 12 hosts."
)


@pytest.mark.parametrize("width", [60, 72, 100])
def test_hard_wrapped_text_gives_the_same_timeline_as_unwrapped(width):
    """TXT exports and text pasted from a PDF break lines at a margin, often before a capital, a digit or an
    indicator; the timeline must not change."""
    import textwrap

    heading = "Initial Access"
    plain = f"{heading}\n{WRAPPED_PARAGRAPH}\nIndicators:\n- update-check[.]net"
    wrapped = f"{heading}\n\n{textwrap.fill(WRAPPED_PARAGRAPH, width)}\n\nIndicators:\n- update-check[.]net"
    assert split_sentences(wrapped) == split_sentences(plain)
    assert len(split_sentences(wrapped)) == 3
    assert "update-check[.]net" in split_sentences(wrapped)[0]  # a hyphen at a break is kept, never deleted


def test_hyphen_at_a_line_break_is_kept_and_bullets_are_trimmed():
    text = (
        "The loader downloaded its payload from update-\ncheck[.]net over HTTPS on port 443 that day.\n"
        "• Their operations have resulted in ransomware infections."
    )
    sentences = split_sentences(text)
    assert sentences == [
        "The loader downloaded its payload from update-check[.]net over HTTPS on port 443 that day.",
        "Their operations have resulted in ransomware infections.",
    ]


def test_one_paragraph_per_line_text_is_not_treated_as_wrapped():
    # D2 and pasted web text: each line is a paragraph; a line without a full stop must not swallow the next one
    lines = [WRAPPED_PARAGRAPH] * 3 + ["Hackers use leaked ransomware to attack banks"] + [WRAPPED_PARAGRAPH] * 3
    assert len(split_sentences("\n".join(lines))) == 18


def test_a_url_longer_than_the_line_is_joined_back_in_wrapped_text():
    import textwrap

    url = "http://kwvhrdibgmmpkhkidrby4mccwqpds5za6uo2thcw5gz75qncv7rbhyad.onion"
    paragraph = f"The ransom note tells victims to visit {url} and enter their personal ID to see the demand."
    wrapped = "\n\n".join([textwrap.fill(paragraph, 50)] * 3)
    assert all(url in s for s in split_sentences(wrapped))
    # a complete URL at the end of an ordinary line is not glued to the next word
    assert split_sentences("It downloads https://t.co/2hay2UVnxo\nand a file called hrms.exe from the server.") == [
        "It downloads https://t.co/2hay2UVnxo and a file called hrms.exe from the server."
    ]
