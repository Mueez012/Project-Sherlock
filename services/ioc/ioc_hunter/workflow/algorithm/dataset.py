"""Incremental D2 preparation using its existing report/sentence identities."""
from __future__ import annotations

from dataclasses import asdict
from hashlib import sha256
from importlib.metadata import PackageNotFoundError, version
import json
import os
from pathlib import Path
import time
from uuid import uuid4

from ...evidence import utc_now
from ...extraction import extract_presplit_report
from ...extraction.positions import locate_occurrences, sentence_positions
from ...models import IOC, identity
from ..coordination import ExecutionCoordinator
from ..models import node_id, stable_id

SCHEMA_VERSION = 1
EXTRACTION_VERSION = "d2-presplit-v1"
SPLITS = ("train", "valid", "test")


def atomic_json(path, payload):
    """Replace one complete record; unfinished temporary files are never inputs."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_name(f".{target.name}.{uuid4().hex}.tmp")
    try:
        with temporary.open("w", encoding="utf-8", newline="\n") as handle:
            json.dump(payload, handle, ensure_ascii=False, allow_nan=False, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        temporary.replace(target)
    finally:
        if temporary.exists():
            temporary.unlink()


def _digest_file(path):
    digest = sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _package_version(name):
    try:
        return version(name)
    except PackageNotFoundError:
        return "unavailable"


def _validate_report(report):
    if (not isinstance(report, dict) or type(report.get("report_id")) is not int
            or report["report_id"] < 1 or not isinstance(report.get("text"), str)
            or not report["text"].strip() or not isinstance(report.get("sentences"), list)
            or not report["sentences"] or any(not isinstance(item, str) for item in report["sentences"])):
        raise ValueError("D2 report requires a positive report_id, original text and saved sentence list")


def prepare_report(report, *, split, build_id, source_file="", include_references=False,
                   extended_types=False):
    """Prepare one validated report; public for bounded callers and offline tests."""
    started = time.monotonic()
    _validate_report(report)
    report_id = report["report_id"]
    source = f"d2:{report_id}"
    result = extract_presplit_report(report["text"], report["sentences"], source=source,
                                     include_references=include_references,
                                     extended_types=extended_types)
    extraction = asdict(result)
    positions = sentence_positions(report["text"], result.sentences, report_id=report_id,
                                   excluded_sections=result.excluded_sections)
    extraction["passages"] = [{"id": item["id"], "text": item["text"],
                                "sentence_index": item["sentence_index"]} for item in positions]
    text_hash = sha256(report["text"].encode("utf-8")).hexdigest()
    extraction_id = stable_id(build_id, report_id, text_hash)
    entities, associations, occurrences, diagnostics = {}, [], [], []
    for index, matches in enumerate(result.matches):
        position = positions[index]
        if position["position_status"] != "located":
            diagnostics.append({"kind": "sentence_position_unavailable", "sentence_index": index})
        for kind, value in matches:
            try:
                canonical = identity(IOC(value, kind))
            except ValueError as error:
                diagnostics.append({"kind": "invalid_extracted_ioc", "type": kind, "value": value,
                                    "message": str(error), "sentence_index": index})
                continue
            key = node_id(IOC(canonical[1], canonical[0]))
            entity = entities.setdefault(key, {"id": key, "type": canonical[0], "value": canonical[1],
                                                "context": [], "source": source, "sentence_indices": []})
            if index not in entity["sentence_indices"]:
                entity["sentence_indices"].append(index)
                entity["context"].append(position["text"])
            association_id = stable_id(extraction_id, key, position["id"])
            located = locate_occurrences(position, canonical[0], canonical[1])
            associations.append({"id": association_id, "ioc_id": key, "sentence_id": position["id"],
                                 "report_id": report_id, "sentence_index": index,
                                 "location_status": "located" if located else "unavailable"})
            for occurrence in located:
                occurrences.append({"id": stable_id(association_id, occurrence["char_start"],
                                                      occurrence["char_end"], occurrence["location_kind"]),
                                    "association_id": association_id, "ioc_id": key,
                                    "sentence_id": position["id"], "sentence_index": index,
                                    **occurrence})
    stats = {"unique_iocs": len(entities), "ioc_sentence_associations": len(associations),
             "located_occurrences": len(occurrences),
             "unlocated_associations": sum(item["location_status"] == "unavailable" for item in associations),
             "sentences": len(positions), "excluded_sentences": sum(item["excluded"] for item in positions),
             "unavailable_sentence_positions": sum(item["position_status"] != "located" for item in positions)}
    return {
        "schema_version": SCHEMA_VERSION, "build_id": build_id, "extraction_id": extraction_id,
        "report_key": str(report_id), "report": {"report_id": report_id, "split": split,
            "group": report.get("group"), "label": report.get("label"),
            "cut_by_excel": report.get("cut_by_excel", False), "source_file": str(source_file)},
        "text": report["text"], "text_sha256": text_hash,
        "sentence_basis": {"name": "d2_saved_sentences", "index_base": 0,
                           "offset_unit": "unicode_code_points", "end_exclusive": True},
        "sentences": positions, "iocs": list(entities.values()), "associations": associations,
        "occurrences": occurrences, "extraction": extraction, "statistics": stats,
        "extraction_options": {"include_references": include_references, "extended_types": extended_types},
        "preparation": {"version": EXTRACTION_VERSION, "status": "prepared", "created_at": utc_now(),
                        "elapsed_seconds": time.monotonic() - started,
                        "include_references": include_references, "extended_types": extended_types,
                        "diagnostics": diagnostics},
    }


def load_prepared(path):
    artifact = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(artifact, dict) or artifact.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("Unsupported prepared dataset schema")
    report_id = artifact.get("report", {}).get("report_id")
    text, extraction = artifact.get("text"), artifact.get("extraction", {})
    if (type(report_id) is not int or report_id < 1 or artifact.get("report_key") != str(report_id)
            or not isinstance(text, str) or sha256(text.encode()).hexdigest() != artifact.get("text_sha256")):
        raise ValueError("Prepared report identity/text does not match its record")
    if artifact.get("extraction_id") != stable_id(artifact.get("build_id"), report_id, artifact["text_sha256"]):
        raise ValueError("Prepared extraction identity does not match its report")
    if not isinstance(extraction, dict) or extraction.get("original_text") != text:
        raise ValueError("Prepared extraction does not preserve its original report text")
    sentences = extraction.get("sentences")
    records, matches = artifact.get("sentences"), extraction.get("matches")
    if not isinstance(sentences, list) or not isinstance(records, list) or not isinstance(matches, list) or not (
            len(sentences) == len(records) == len(matches)):
        raise ValueError("Prepared report requires aligned saved sentences and matches")
    for index, record in enumerate(records):
        if (not isinstance(record, dict) or record.get("id") != f"{report_id}:s{index}" or record.get("sentence_index") != index
                or record.get("text") != sentences[index]):
            raise ValueError("Prepared sentence ID/index/text mismatch")
        start, end = record.get("char_start"), record.get("char_end")
        if start is not None and (type(start) is not int or type(end) is not int
                                  or start < 0 or end < start or text[start:end] != record["text"]):
            raise ValueError("Prepared sentence span does not match original text")
    passages = extraction.get("passages")
    if not isinstance(passages, list) or len(passages) != len(records) or any(
            not isinstance(passage, dict) or passage.get("id") != record["id"] or passage.get("sentence_index") != index
            or passage.get("text") != record["text"]
            for index, (record, passage) in enumerate(zip(records, passages))):
        raise ValueError("Prepared passages differ from the saved sentence identities")
    expected = {}
    for index, pairs in enumerate(matches):
        if not isinstance(pairs, list):
            raise ValueError("Prepared matches must contain one list per sentence")
        for pair in pairs:
            if not isinstance(pair, (list, tuple)) or len(pair) != 2:
                raise ValueError("Prepared match must contain type and value")
            try:
                kind, value = identity(IOC(pair[1], pair[0]))
            except (ValueError, TypeError):
                continue  # Preserved extraction diagnostics may contain rejected values.
            expected.setdefault(node_id(IOC(value, kind)), {"type": kind, "value": value, "indices": []})
            if index not in expected[node_id(IOC(value, kind))]["indices"]:
                expected[node_id(IOC(value, kind))]["indices"].append(index)
    actual = {}
    for item in artifact.get("iocs", []):
        kind, value = identity(IOC(item["value"], item["type"]))
        key = node_id(IOC(value, kind))
        if key in actual or item.get("id") != key or item.get("sentence_indices") != expected.get(key, {}).get("indices"):
            raise ValueError("Prepared IOC identity/positions differ from saved matches")
        actual[key] = {"type": kind, "value": value, "indices": item["sentence_indices"]}
    if actual != expected:
        raise ValueError("Prepared IOC entities differ from saved matches")
    return artifact


def prepare_dataset(source_dir, output_dir, *, splits=None, report_ids=None, max_reports=None,
                    include_references=False, extended_types=False):
    source_dir, output_dir = Path(source_dir).resolve(), Path(output_dir).resolve()
    if type(include_references) is not bool or type(extended_types) is not bool:
        raise ValueError("Extraction options must be Boolean")
    if max_reports is not None and (type(max_reports) is not int or max_reports < 1):
        raise ValueError("max_reports must be a positive integer")
    if isinstance(splits, str):
        splits = [splits]
    selected_splits = tuple(splits or [item for item in SPLITS if (source_dir / f"{item}.jsonl").is_file()])
    if not selected_splits or any(item not in SPLITS or not (source_dir / f"{item}.jsonl").is_file() for item in selected_splits):
        raise ValueError("Select available D2 train/valid/test JSONL splits")
    selected_ids = None if report_ids is None else set(report_ids)
    if selected_ids is not None and any(type(value) is not int or value < 1 for value in selected_ids):
        raise ValueError("report_ids must contain positive integers")
    sources = {path.name: _digest_file(path) for path in sorted(source_dir.glob("*.jsonl"))}
    if (source_dir / "groups.json").is_file():
        sources["groups.json"] = _digest_file(source_dir / "groups.json")
    options = {"include_references": include_references, "extended_types": extended_types,
               "extraction_version": EXTRACTION_VERSION, "ioc_finder_version": _package_version("ioc-finder")}
    build_id = stable_id("d2", sources, options)
    output_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = output_dir / "manifest.json"
    with ExecutionCoordinator(output_dir).claim("dataset:prepare"):
        if manifest_path.exists():
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            if manifest.get("build_id") != build_id:
                raise ValueError("Dataset source/extraction settings changed; choose a different build directory")
        else:
            manifest = {"schema_version": SCHEMA_VERSION, "id": build_id, "build_id": build_id,
                        "source_dir": str(source_dir), "output_dir": str(output_dir),
                        "source_files": sources, "options": options, "created_at": utc_now(), "reports": []}
        entries = {str(item["report_id"]): item for item in manifest["reports"]}
        count, seen = 0, set()
        for split in SPLITS:
            if split not in selected_splits:
                continue
            path = source_dir / f"{split}.jsonl"
            with path.open(encoding="utf-8-sig") as handle:
                rows = [json.loads(line) for line in handle if line.strip()]
            for report in sorted(rows, key=lambda item: item.get("report_id", 0)):
                report_id = report.get("report_id")
                if type(report_id) is not int or report_id < 1:
                    raise ValueError("D2 source row has no positive report_id")
                if report_id in seen:
                    raise ValueError(f"Duplicate D2 report_id: {report_id}")
                seen.add(report_id)
                if selected_ids is not None and report_id not in selected_ids:
                    continue
                if max_reports is not None and count >= max_reports:
                    break
                count += 1
                key = str(report_id)
                destination = output_dir / "reports" / f"{key}.json"
                entry = {"report_id": report_id, "report_key": key, "split": split,
                         "path": f"reports/{key}.json", "status": "prepared"}
                try:
                    _validate_report(report)
                    if destination.exists():
                        artifact = load_prepared(destination)
                        if artifact["build_id"] != build_id or artifact["text"] != report["text"]:
                            raise ValueError("Saved extraction differs from this D2 build")
                    else:
                        artifact = prepare_report(report, split=split, build_id=build_id, source_file=path.name,
                                                  include_references=include_references, extended_types=extended_types)
                        atomic_json(destination, artifact)
                    entry["extraction_id"] = artifact["extraction_id"]
                except (ValueError, OSError) as error:
                    entry.update(status="failed", error=str(error))
                entries[key] = entry
                manifest["reports"] = sorted(entries.values(), key=lambda item: (SPLITS.index(item["split"]), item["report_id"]))
                manifest["counts"] = {"prepared": sum(item["status"] == "prepared" for item in entries.values()),
                                      "failed": sum(item["status"] == "failed" for item in entries.values()),
                                      "total": len(entries)}
                manifest["updated_at"] = utc_now()
                atomic_json(manifest_path, manifest)
            if max_reports is not None and count >= max_reports:
                break
        if "counts" not in manifest:
            manifest["counts"] = {"prepared": 0, "failed": 0, "total": 0}
        atomic_json(manifest_path, manifest)
        return manifest


def iter_prepared(build_dir):
    directory = Path(build_dir)
    manifest = json.loads((directory / "manifest.json").read_text(encoding="utf-8"))
    if manifest.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("Unsupported dataset manifest schema")
    for entry in manifest["reports"]:
        if entry.get("status") != "prepared":
            continue
        path = (directory / entry["path"]).resolve()
        if not path.is_relative_to(directory.resolve()):
            raise ValueError("Prepared report path left its build directory")
        artifact = load_prepared(path)
        if artifact["build_id"] != manifest["build_id"]:
            raise ValueError("Prepared report belongs to a different build")
        yield artifact
