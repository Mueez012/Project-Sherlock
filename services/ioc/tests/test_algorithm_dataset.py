"""D2 sentence identity, truthful locations and incremental local preparation."""
import json
from pathlib import Path
from unittest.mock import patch

import pytest

from ioc_hunter.extraction import extract_presplit_report
from ioc_hunter.workflow.algorithm.dataset import (
    atomic_json, iter_prepared, load_prepared, prepare_dataset, prepare_report,
)


def report(identifier=17):
    sentences = ["The loader contacted Example[.]COM twice: Example[.]COM.",
                 "It used 192.0.2.10.", "References", "https://publisher.example/article"]
    return {"report_id": identifier, "group": "Actor", "label": 0, "cut_by_excel": True,
            "text": "\n".join(sentences), "sentences": sentences}


def write_source(directory, *rows):
    directory.mkdir()
    (directory / "train.jsonl").write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")


def test_presplit_path_never_splits_and_preserves_reference_indices():
    row = report()
    with patch("ioc_hunter.extraction.pipeline.split_sentences", side_effect=AssertionError("split called")), \
            patch("ioc_hunter.extraction.pipeline.create_sentencizer", side_effect=AssertionError("spaCy called")):
        result = extract_presplit_report(row["text"], row["sentences"])
    assert result.sentences == row["sentences"]
    assert len(result.matches) == 4
    assert not result.matches[2] and not result.matches[3]
    assert ("domain", "example.com") in result.matches[0]


def test_readable_sentence_ids_repeat_mentions_and_original_spelling():
    row = report()
    artifact = prepare_report(row, split="train", build_id="test")
    assert [item["id"] for item in artifact["sentences"]] == ["17:s0", "17:s1", "17:s2", "17:s3"]
    assert "hash" not in artifact["sentence_basis"]
    assert artifact["sentences"][3]["excluded"]
    domain = next(item for item in artifact["iocs"] if item["value"] == "example.com")
    assert domain["sentence_indices"] == [0]
    occurrences = [item for item in artifact["occurrences"] if item["ioc_id"] == domain["id"]]
    assert len(occurrences) == 2
    assert all(row["text"][item["char_start"]:item["char_end"]] == item["raw_value"] == "Example[.]COM"
               for item in occurrences)
    assert artifact["report"]["cut_by_excel"]
    assert artifact["extraction_options"] == {"include_references": False, "extended_types": False}
    assert not any(item["value"] == "publisher.example" for item in artifact["iocs"])


def test_identical_sentences_align_to_distinct_source_positions_and_unavailable_is_null():
    saved = ["Contact example.com.", "Contact example.com.", "Unknown 192.0.2.20."]
    row = {**report(), "text": "Contact example.com.\nContact example.com.", "sentences": saved}
    artifact = prepare_report(row, split="test", build_id="test")
    first, second, missing = artifact["sentences"]
    assert first["char_start"] == 0 and second["char_start"] > first["char_end"]
    assert missing["char_start"] is missing["char_end"] is None
    ip = next(item for item in artifact["iocs"] if item["value"] == "192.0.2.20")
    association = next(item for item in artifact["associations"] if item["ioc_id"] == ip["id"])
    assert association["sentence_index"] == 2 and association["location_status"] == "unavailable"


def test_mixed_version_and_address_does_not_locate_version_occurrence():
    sentence = "Version 1.2.3.4 contacted IP 1.2.3.4."
    artifact = prepare_report({**report(), "text": sentence, "sentences": [sentence]}, split="train", build_id="test")
    ip = next(item for item in artifact["iocs"] if item["value"] == "1.2.3.4")
    located = [item for item in artifact["occurrences"] if item["ioc_id"] == ip["id"]]
    assert len(located) == 1
    assert located[0]["char_start"] == sentence.rindex("1.2.3.4")


def test_preparation_resumes_after_completed_artifact_and_expands_subset(tmp_path):
    source, output = tmp_path / "source", tmp_path / "build"
    write_source(source, report(17), report(18))
    first = prepare_dataset(source, output, max_reports=1)
    assert first["counts"]["prepared"] == 1
    assert first["reports"][0]["path"] == "reports/17.json"
    with patch("ioc_hunter.workflow.algorithm.dataset.prepare_report", side_effect=AssertionError("re-extracted")):
        repeated = prepare_dataset(source, output, max_reports=1)
    assert repeated["id"] == first["id"]
    complete = prepare_dataset(source, output)
    assert complete["counts"] == {"prepared": 2, "failed": 0, "total": 2}
    assert [item["report"]["report_id"] for item in iter_prepared(output)] == [17, 18]
    assert not list(output.rglob("*.tmp"))


def test_source_or_settings_change_requires_a_new_build(tmp_path):
    source, output = tmp_path / "source", tmp_path / "build"
    write_source(source, report())
    prepare_dataset(source, output)
    with pytest.raises(ValueError, match="settings changed"):
        prepare_dataset(source, output, extended_types=True)


def test_saved_sentence_tampering_rejected_without_network(tmp_path):
    path = tmp_path / "report.json"
    artifact = prepare_report(report(), split="train", build_id="test")
    atomic_json(path, artifact)
    assert load_prepared(path)["report"]["report_id"] == 17
    artifact["sentences"][0]["sentence_index"] = 5
    atomic_json(path, artifact)
    with pytest.raises(ValueError, match="sentence ID/index/text"):
        load_prepared(path)


def test_report_key_cannot_escape_export_directory(tmp_path):
    path = tmp_path / "report.json"
    artifact = prepare_report(report(), split="train", build_id="test")
    artifact["report_key"] = "../../outside"
    atomic_json(path, artifact)
    with pytest.raises(ValueError, match="identity/text"):
        load_prepared(path)


def test_url_domain_component_is_labelled_and_readable_ids_do_not_change_with_build():
    sentence = "Downloaded https://example.com/payload."
    row = {**report(), "text": sentence, "sentences": [sentence]}
    first = prepare_report(row, split="train", build_id="a")
    second = prepare_report(row, split="train", build_id="b")
    assert first["sentences"][0]["id"] == second["sentences"][0]["id"]
    domain = next(item for item in first["iocs"] if item["type"] == "domain")
    occurrence = next(item for item in first["occurrences"] if item["ioc_id"] == domain["id"])
    assert occurrence["location_kind"] == "derived_component"
