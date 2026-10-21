from threatmamba.contracts import IOCType
from threatmamba.ioc import RegexIOCExtractor
from threatmamba.text import split_sentences
from threatmamba.ttp import KeywordTTPExtractor


def test_split_sentences_on_punctuation_and_newlines():
    assert split_sentences("First one. Second one!\nThird") == ["First one.", "Second one!", "Third"]


def test_split_sentences_follows_the_d2_rules():
    # no minimum length: a one-letter piece is kept, as in the D2 dataset
    assert split_sentences("Now, see what happened. J\nWe got it.") == ["Now, see what happened.", "J", "We got it."]
    # a full stop followed by a lowercase word or a digit straight after does not end a sentence
    assert split_sentences("Version 2.0 shipped. then it broke.") == ["Version 2.0 shipped. then it broke."]


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
