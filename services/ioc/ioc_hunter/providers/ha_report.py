"""Decode Hybrid Analysis unified report data and concrete activity fields.

Next flight scripts are treated as text containing JSON, never executed. The
parser does not inspect graph state, assign confidence or validate API names.
"""
from html.parser import HTMLParser
import json
import re
from urllib.parse import urlsplit

from ..models import normalize
from ..transport.models import LookupError, allowed_url


class ReportScripts(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=False)
        self.scripts = []
        self._script = None

    def handle_starttag(self, tag, attrs):
        if tag == "script":
            self._script = []

    def handle_data(self, data):
        if self._script is not None:
            self._script.append(data)

    def handle_endtag(self, tag):
        if tag == "script" and self._script is not None:
            self.scripts.append("".join(self._script))
            self._script = None


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON key")
        result[key] = value
    return result


def read_report(document) -> dict:
    """Decode the current page's one unified initialData report."""
    if not allowed_url("hybridanalysis", document.url):
        raise LookupError("invalid_response", "Hybrid Analysis report left the provider")
    page = re.fullmatch(r"/sample/([0-9a-fA-F]{64})/?", urlsplit(document.url).path)
    if not page:
        raise LookupError("invalid_response", "Unexpected Hybrid Analysis report page")
    expected = normalize("sha256", page.group(1))
    if document.format != "html":
        raise LookupError("parse_error", "Expected Hybrid Analysis report HTML")
    parser = ReportScripts()
    parser.feed(document.body)
    decoder = json.JSONDecoder(object_pairs_hook=_unique_object)
    fragments = []
    for script in parser.scripts:
        for marker in re.finditer(r"self\.__next_f\.push\(", script):
            try:
                entry, end = decoder.raw_decode(script[marker.end():])
            except (ValueError, TypeError, RecursionError):
                continue
            if (isinstance(entry, list) and len(entry) == 2 and entry[0] == 1
                    and isinstance(entry[1], str)
                    and script[marker.end() + end:].lstrip().startswith(")")):
                fragments.append(entry[1])
    stream = "".join(fragments)
    reports = []
    for marker in re.finditer(r'"initialData"\s*:\s*', stream):
        try:
            value, _ = decoder.raw_decode(stream[marker.end():])
        except (ValueError, TypeError, RecursionError):
            continue
        if isinstance(value, dict) and "schema_version" in value and "sha256" in value:
            if value not in reports:
                reports.append(value)
    if len(reports) != 1:
        lowered = document.body.lower()
        if any(marker in lowered for marker in ("verify you are human", "checking your browser", "captcha")):
            raise LookupError("challenge", "Hybrid Analysis report requires an interactive challenge")
        if "sample not found" in lowered or "report not found" in lowered:
            raise LookupError("not_found", "Hybrid Analysis sample report was not found")
        raise LookupError("parse_error", "Missing or ambiguous Hybrid Analysis unified report data")
    report = reports[0]
    try:
        observed = normalize("sha256", report["sha256"])
        metadata = report["metadata"]
        hashes = metadata["hashes"]
        metadata_hash = normalize("sha256", hashes["sha256"])
    except (ValueError, TypeError, KeyError) as exc:
        raise LookupError("parse_error", "Invalid Hybrid Analysis report identity") from exc
    if observed != expected or metadata_hash != expected:
        raise LookupError("invalid_response", "Hybrid Analysis report belongs to another sample")
    if not isinstance(report.get("activity"), dict) or not isinstance(metadata.get("file_info"), dict):
        raise LookupError("parse_error", "Missing Hybrid Analysis report activity or file metadata")
    return report


def concrete_text(value) -> str:
    """Exclude unresolved React references, empty text and control characters."""
    if not isinstance(value, str):
        return ""
    value = value.strip()
    if not value or re.fullmatch(r"\$(?:[0-9a-fA-F]+|[A-Za-z][A-Za-z0-9]*)", value):
        return ""
    if re.search(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", value):
        return ""
    return value


def output_field_matches(kind: str, locator: str) -> bool:
    """Source field contract for the independent method-correctness guard."""
    patterns = {
        "command_api": r"initialData\.activity\.process_activity\.processes\[\d+\]\.(?:command_line|name|api_calls\[\d+\])",
        "registry": r"initialData\.activity\.registry_activity\.keys_(?:created|modified|deleted)\[\d+\]\.key",
        "filename": r"initialData\.metadata\.file_info\.file_name",
        "url": r"initialData\.(?:activity\.network_activity\.http_requests\[\d+\]\.url|metadata\.(?:file_info|submissions)\.(?:source_url|download_url))",
    }
    return isinstance(locator, str) and re.fullmatch(patterns.get(kind, r"(?!)"), locator) is not None


def _section(report, key):
    value = report["activity"].get(key)
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise LookupError("parse_error", "Invalid Hybrid Analysis activity section: " + key)
    return value


def _rows(section, field):
    rows = section.get(field)
    if rows is None:
        return []
    if not isinstance(rows, list):
        raise LookupError("parse_error", "Invalid Hybrid Analysis activity list: " + field)
    return rows


def command_observations(report):
    """Yield recorded process commands/names and explicitly labelled API calls."""
    section = _section(report, "process_activity")
    for index, process in enumerate(_rows(section, "processes")):
        if not isinstance(process, dict):
            raise LookupError("parse_error", "Invalid Hybrid Analysis process observation")
        for field in ("command_line", "name"):
            value = concrete_text(process.get(field))
            if value:
                yield value, f"initialData.activity.process_activity.processes[{index}].{field}", process
        # Some reports may carry explicit calls; imported DLLs remain metadata
        # and are deliberately not transformed into runtime API observations.
        for call_index, call in enumerate(_rows(process, "api_calls")):
            value = concrete_text(call if isinstance(call, str) else call.get("name") if isinstance(call, dict) else None)
            if value:
                yield value, f"initialData.activity.process_activity.processes[{index}].api_calls[{call_index}]", call


def clean_registry_key(value) -> str:
    value = concrete_text(value)
    # The observed unified report repeats abbreviated hive prefixes. Collapse
    # only exact adjacent repetitions, preserving the source row in evidence.
    for hive in ("HKLM", "HKCU", "HKCR", "HKCC", "HKU"):
        value = re.sub(r"^(?:" + hive + r"){2,}(?=\\)", hive, value, flags=re.I)
    return value


def registry_observations(report):
    section = _section(report, "registry_activity")
    for field in ("keys_created", "keys_modified", "keys_deleted"):
        for index, row in enumerate(_rows(section, field)):
            if not isinstance(row, dict):
                raise LookupError("parse_error", "Invalid Hybrid Analysis registry observation")
            value = clean_registry_key(row.get("key"))
            if value:
                yield value, f"initialData.activity.registry_activity.{field}[{index}].key", row


def filename_observations(report):
    info = report["metadata"]["file_info"]
    value = concrete_text(info.get("file_name"))
    if value:
        yield value, "initialData.metadata.file_info.file_name", {"file_name": info["file_name"]}


def url_observations(report):
    """Read explicit HTTP observations and labelled source/download URLs."""
    section = _section(report, "network_activity")
    for index, row in enumerate(_rows(section, "http_requests")):
        if not isinstance(row, dict):
            raise LookupError("parse_error", "Invalid Hybrid Analysis HTTP observation")
        value = concrete_text(row.get("url"))
        if value:
            yield value, f"initialData.activity.network_activity.http_requests[{index}].url", row
    # These optional explicit labels are never inferred from process text,
    # arbitrary anchors, URL basenames or contacted-domain records.
    for section_name in ("file_info", "submissions"):
        section = report["metadata"].get(section_name)
        if section is None:
            continue
        if not isinstance(section, dict):
            raise LookupError("parse_error", "Invalid Hybrid Analysis URL metadata")
        for field in ("source_url", "download_url"):
            value = concrete_text(section.get(field))
            if value:
                yield value, f"initialData.metadata.{section_name}.{field}", {field: section[field]}
