from threatmamba.contracts import IOCType
from threatmamba.ioc import RegexIOCExtractor
from threatmamba.text import split_sentences
from threatmamba.ttp import KeywordTTPExtractor


def test_split_sentences_on_punctuation_and_newlines():
    assert split_sentences("First one. Second one!\nThird") == ["First one.", "Second one!", "Third"]


def test_ioc_extractor_refangs_and_types():
    sents = ["C2 at 185.12.45[.]201 and hxxp://evil[.]info/a.ps1 plus CVE-2021-44228."]
    iocs = {(i.type, i.value) for i in RegexIOCExtractor().extract(sents)}
    assert (IOCType.ipv4, "185.12.45.201") in iocs
    assert (IOCType.url, "http://evil.info/a.ps1") in iocs
    assert (IOCType.cve, "CVE-2021-44228") in iocs


def test_ioc_extractor_prefers_longest_hash_and_dedupes():
    h = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
    iocs = RegexIOCExtractor().extract([f"hash {h}", f"again {h}"])
    assert [(i.type, i.sentence_index) for i in iocs] == [(IOCType.sha256, 0)]


def test_ttp_keyword_extractor_maps_sentences():
    hits = KeywordTTPExtractor().predict(["A spear-phishing email arrived.", "Nothing here.", "PowerShell ran."])
    assert {(h.technique_id, h.sentence_index) for h in hits} == {("T1566", 0), ("T1059", 2)}
    assert all(0 <= h.score <= 1 for h in hits)
