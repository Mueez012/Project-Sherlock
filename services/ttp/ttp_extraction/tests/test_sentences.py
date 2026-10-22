from ttp_extraction.preprocessing.sentences import split_sentences


def test_splits_plain_sentences():
    text = "The actor sent a phishing email. The victim opened the attachment."
    assert split_sentences(text) == [
        "The actor sent a phishing email.",
        "The victim opened the attachment.",
    ]


def test_does_not_split_inside_a_file_name():
    assert split_sentences("It dropped evil.exe to disk.") == ["It dropped evil.exe to disk."]


def test_blank_lines_separate_paragraphs():
    text = "Initial Access\n\nThe actor sent\na phishing email. It worked."
    assert split_sentences(text) == [
        "Initial Access",
        "The actor sent a phishing email.",
        "It worked.",
    ]


def test_empty_input_gives_no_sentences():
    assert split_sentences("  \n\n  ") == []