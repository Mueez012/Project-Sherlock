"""HA source-parser and lookup-boundary regressions.

Captured report fields have provenance in fixtures/hybridanalysis/README.md.
Search HTML, API-call fields and URL-positive cases below are synthetic; they
do not establish live discovery, account entitlement or current API availability.
"""
from dataclasses import replace
from html import escape
import json
from pathlib import Path
from unittest.mock import patch
from urllib.parse import quote

import pytest

from ioc_hunter import IOC, LookupClient, LookupError, get_method
from ioc_hunter.evidence import LookupRecord
from ioc_hunter.providers import hybridanalysis
from ioc_hunter.providers.ha_report import read_report
from ioc_hunter.providers.ha_search import haql_query
from ioc_hunter.storage import EvidenceStore
from ioc_hunter.transport import Document
from ioc_hunter.validation import validate_edge


FIXTURE = Path(__file__).parent / "fixtures" / "hybridanalysis" / "unified_report_captured_minimized.json"
CAPTURED_SHA256 = "2e7aa640b2da6d9350afba1b8ad0b65bc85ac335dde42f08cd540da8580e2a78"
SYNTHETIC_SHA256 = "c" * 64
SYNTHETIC_HASHES = {"md5": "a" * 32, "sha1": "b" * 40, "sha256": SYNTHETIC_SHA256}
REGISTRY = "HKCU\\Software\\RecordedProviderKey"
RECORDED_URL = "https://www.python.org/downloads/"


def captured_report():
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def synthetic_report():
    """Schema-shaped test data; API/URL-positive fields are not live captures."""
    return {
        "schema_version": "1.0.17", "sha256": SYNTHETIC_SHA256,
        "overall_status": "SUCCESS", "unified_at": "2026-11-10T00:00:00Z",
        "metadata": {"hashes": dict(SYNTHETIC_HASHES),
                     "file_info": {"file_name": "returned-name.bin"}, "submissions": {}},
        "activity": {
            "process_activity": {"processes": [
                {"name": "powershell.exe", "command_line": "powershell.exe -NoProfile",
                 "api_calls": ["ProviderFunction42"]}]},
            "registry_activity": {"keys_created": [{"key": REGISTRY}],
                                  "keys_modified": None, "keys_deleted": None},
            "network_activity": {"http_requests": [{"url": RECORDED_URL}]},
        },
    }


def flight_html(report=None, *, stream=None, fragments=2):
    """Reconstructed actual Next protocol, with arbitrary transport fragments."""
    if stream is None:
        stream = '0:["$","SyntheticReport",null,{"initialData":' + json.dumps(report) + "}]\n"
    step = max(1, len(stream) // fragments)
    pieces = [stream[index:index + step] for index in range(0, len(stream), step)]
    scripts = "".join("<script>self.__next_f.push(" + json.dumps([1, piece]) + ");</script>" for piece in pieces)
    return "<!doctype html><html><body>" + scripts + "</body></html>"


def report_document(report=None, *, sample_hash=None, body=None, context=None):
    report = synthetic_report() if report is None else report
    value = sample_hash or report["sha256"]
    return Document(f"https://hybrid-analysis.com/sample/{value}",
                    flight_html(report) if body is None else body, "html", "browser",
                    diagnostics={"request_context": context or {"stage": "report", "sample_sha256": value}})


def search_document(query, hashes=(SYNTHETIC_SHA256,), *, empty=False, window="Last 1 hour",
                    input_query=None, page_query=None, result_text=""):
    """Synthetic rendered HTML following the captured form/result structure."""
    expected = haql_query(query)
    links = "".join(f'<a href="/sample/{value}">sample</a>' for value in hashes)
    completed = "<h4>No results found</h4>" if empty else links + result_text
    body = ('<form role="search"><input role="combobox" value="' +
            escape(expected if input_query is None else input_query, quote=True) + '"></form>' +
            '<span>' + escape(window) + '</span><section class="synthetic_results">' + completed +
            '</section><a href="/sample/' + "f" * 64 + '">outside results</a>')
    url = "https://hybrid-analysis.com/search?q=" + quote(expected if page_query is None else page_query, safe="")
    return Document(url, body, "html", "browser", diagnostics={"request_context": {"stage": "search"}})


class OfflineBrowser:
    offline = True

    def __init__(self, report=None, *, hashes=(SYNTHETIC_SHA256,)):
        self.report = synthetic_report() if report is None else report
        self.hashes = hashes
        self.requests = []

    def fetch(self, request):
        self.requests.append(request)
        if request.context.get("stage") == "search":
            # The request's q value is deliberately retained to exercise the
            # provider's own query binding, not a separately inferred query.
            query = request.context["haql_query"]
            links = "".join(f'<a href="/sample/{value}">sample</a>' for value in self.hashes)
            body = ('<form role="search"><input role="combobox" value="' + escape(query, quote=True) +
                    '"></form><span>Last 1 hour</span><section class="synthetic_results">' + links + '</section>')
            return Document(request.url, body, "html", "browser")
        return report_document(self.report)


def test_captured_report_commands_and_registry_fields_decode_across_next_fragments():
    source = captured_report()
    document = report_document(source, body=flight_html(source, fragments=7))
    command_query = IOC(CAPTURED_SHA256, "sha256")
    command_method = get_method("hybridanalysis.sha256_to_command_api")
    commands = hybridanalysis.parse_document(command_query, command_method, document)
    values = {item.ioc.value for item in commands.observations}
    assert "powershell.exe" in values
    assert source["activity"]["process_activity"]["processes"][0]["command_line"] in values
    assert len(values) == 2
    assert all(validate_edge(command_query, item.ioc, command_method, item.evidence).accepted
               for item in commands.observations)

    # A different filename does not impose a new report-name equality gate.
    query = IOC("search-input-name.bin", "filename")
    method = get_method("hybridanalysis.filename_to_registry")
    keys = hybridanalysis.parse_document(query, method, document).observations
    assert {item.ioc.value for item in keys} == {
        "HKCU\\SOFTWARE\\MICROSOFT\\SYSTEMCERTIFICATES\\CA\\",
        "HKCU\\SOFTWARE\\MICROSOFT\\SYSTEMCERTIFICATES\\CA\\CERTIFICATES\\",
    }
    assert len(keys) == 2
    assert "HKCUHKCU" in keys[0].evidence.excerpt
    assert all(validate_edge(query, item.ioc, method, item.evidence).accepted for item in keys)


def test_actual_captured_flight_script_decodes_without_reconstructed_transport_json():
    """Keep one actual source script intact, rather than regenerating its JSON."""
    fixture = FIXTURE.with_name("unified_report_flight_captured.html")
    document = Document(f"https://hybrid-analysis.com/sample/{CAPTURED_SHA256}",
                        fixture.read_text(encoding="utf-8"), "html")
    report = read_report(document)
    assert report["sha256"] == CAPTURED_SHA256 and report["overall_status"] == "SUCCESS"
    query = IOC(CAPTURED_SHA256, "sha256")
    commands = hybridanalysis.parse_document(query, get_method("hybridanalysis.sha256_to_command_api"), document)
    assert len(commands.observations) == 2
    assert "powershell.exe" in {item.ioc.value for item in commands.observations}
    registry = hybridanalysis.parse_document(IOC("source-search.bin", "filename"),
                                             get_method("hybridanalysis.filename_to_registry"), document)
    assert len(registry.observations) == 46
    urls = hybridanalysis.parse_document(IOC("source-search.bin", "filename"),
                                         get_method("hybridanalysis.filename_to_url"), document)
    assert not urls.observations and urls.reason == "url_unavailable"


@pytest.mark.parametrize("kind,value,output", [
    ("md5", SYNTHETIC_HASHES["md5"], "command_api"),
    ("sha1", SYNTHETIC_HASHES["sha1"], "command_api"),
    ("sha256", SYNTHETIC_HASHES["sha256"], "command_api"),
    ("filename", "requested-name.bin", "command_api"),
    ("filename", "requested-name.bin", "registry"),
    ("filename", "requested-name.bin", "url"),
    ("registry", "HKCU\\Software\\SearchInput", "filename"),
    ("command_api", "providerfunction42", "registry"),
])
def test_all_eight_methods_execute_shared_pipeline_with_synthetic_source_data(tmp_path, kind, value, output):
    browser = OfflineBrowser()
    client = LookupClient(store=EvidenceStore(tmp_path), browser=browser, api_keys={}, interval=0, cache_ttl=0)
    query = IOC(value, kind, ["Original investigation context"], "cti report")
    with patch("socket.socket.connect", side_effect=AssertionError("Unexpected external request")):
        record = client.lookup_detailed(query, f"hybridanalysis.{kind}_to_{output}")
    assert record.outputs and all(ioc.type == output for ioc in record.outputs)
    assert not record.rejected and not record.cache_hit
    assert len(browser.requests) == (1 if kind == "sha256" else 2)
    assert all(request.capture_html and not request.headers for request in browser.requests)
    assert all(evidence.query_value == value for evidence in record.evidence)
    assert query.context == ["Original investigation context"]
    assert LookupRecord.from_dict(client.store.get_record(record.id)).to_dict() == record.to_dict()
    if kind == "sha256":
        assert record.status == "ok" and record.complete
    else:
        assert record.status == "partial" and "search_time_window_limited" in record.partial_reasons
    if output == "filename":
        assert [ioc.value for ioc in record.outputs] == ["returned-name.bin"]
    if output == "url":
        assert [ioc.value for ioc in record.outputs] == [RECORDED_URL]


def test_report_navigation_deduplicates_sample_links_and_ignores_unrelated_page_links():
    query = IOC("requested-name.bin", "filename")
    method = get_method("hybridanalysis.filename_to_command_api")
    parsed = hybridanalysis.parse_document(query, method, search_document(query, (SYNTHETIC_SHA256,) * 3))
    assert len(parsed.followups) == 1
    assert parsed.followups[0].key == "ha-report:" + SYNTHETIC_SHA256
    assert parsed.observations == []


@pytest.mark.parametrize("kind,value,output", [
    ("md5", SYNTHETIC_HASHES["md5"], "command_api"),
    ("filename", "requested-name.bin", "registry"),
    ("command_api", "ProviderFunction42", "registry"),
])
def test_html_search_declares_observed_post_for_access_error_capture(kind, value, output):
    query = IOC(value, kind)
    method = get_method(f"hybridanalysis.{kind}_to_{output}")
    transport, request = hybridanalysis.requests_for(query, method)[0]
    assert transport == "browser" and request.capture_html
    assert request.bootstrap_paths == ("/bff/proxy/search",)
    assert not request.response_paths
    assert request.integration_version == "2"


@pytest.mark.parametrize("value,kind,field", [
    ('a file "quoted".exe', "filename", "filename"),
    ('HKCU\\Software\\App" OR verdict:malicious', "registry", "content"),
    ('FunctionName" OR content:"anything', "command_api", "content"),
])
def test_haql_inputs_are_quoted_literals_in_one_field(value, kind, field):
    query = haql_query(IOC(value, kind))
    assert query.startswith(field + ":")
    assert json.loads(query[len(field) + 1:]) == value
    requests = hybridanalysis.requests_for(IOC(value, kind), get_method(
        f"hybridanalysis.{kind}_to_" + ("command_api" if kind == "filename" else "filename" if kind == "registry" else "registry")))
    assert requests[0][0] == "browser"
    assert not requests[0][1].response_paths  # No invented private POST body contract.


@pytest.mark.parametrize("change", ["page_query", "input_query"])
def test_search_refuses_another_input_or_page_query(change):
    query = IOC("requested-name.bin", "filename")
    document = search_document(query, **{change: 'filename:"other-name.bin"'})
    with pytest.raises(LookupError) as failure:
        hybridanalysis.parse_document(query, get_method("hybridanalysis.filename_to_registry"), document)
    assert failure.value.status in {"invalid_response", "parse_error"}


def test_completed_empty_search_is_partial_for_the_observed_last_hour_window():
    query = IOC("requested-name.bin", "filename")
    result = hybridanalysis.parse_document(query, get_method("hybridanalysis.filename_to_registry"),
                                          search_document(query, hashes=(), empty=True))
    assert not result.observations and not result.followups
    assert not result.complete and result.reason == "search_time_window_limited"


@pytest.mark.parametrize("text,status", [
    ("Verify you are human", "challenge"),
    ("Login required", "login_required"),
    ("Insufficient permissions", "access_denied"),
    ("Invalid HAQL", "invalid_request"),
])
def test_search_access_or_syntax_errors_are_not_empty_results(text, status):
    query = IOC("requested-name.bin", "filename")
    document = search_document(query, hashes=(), result_text="<h4>" + text + "</h4>")
    with pytest.raises(LookupError) as failure:
        hybridanalysis.parse_document(query, get_method("hybridanalysis.filename_to_registry"), document)
    assert failure.value.status == status


def test_search_shell_without_completed_results_is_not_an_empty_lookup():
    query = IOC("requested-name.bin", "filename")
    with pytest.raises(LookupError) as failure:
        hybridanalysis.parse_document(query, get_method("hybridanalysis.filename_to_registry"),
                                      search_document(query, hashes=()))
    assert failure.value.status == "loading_page"


def test_command_to_registry_requires_runtime_observation_without_an_api_name_whitelist():
    report = synthetic_report()
    method = get_method("hybridanalysis.command_api_to_registry")
    observed = hybridanalysis.parse_document(IOC("ProviderFunction42", "command_api"), method, report_document(report))
    assert [item.ioc.value for item in observed.observations] == [REGISTRY]
    assert observed.observations[0].evidence.facts["runtime_command"] == "ProviderFunction42"
    report["activity"]["process_activity"]["processes"][0].pop("api_calls")
    report["activity"]["process_activity"]["all_imported_dlls"] = ["ProviderFunction42"]
    report["metadata"]["file_info"]["static_string"] = "ProviderFunction42"
    missing = hybridanalysis.parse_document(IOC("ProviderFunction42", "command_api"), method, report_document(report))
    assert missing.observations == [] and missing.reason == "command_api_not_observed"


def test_command_registry_scope_is_recorded_file_activity_without_a_pid_join_requirement():
    report = synthetic_report()
    # The key row has no PID/handle. The workflow still owns edge admission.
    query = IOC("powershell.exe", "command_api")
    method = get_method("hybridanalysis.command_api_to_registry")
    parsed = hybridanalysis.parse_document(query, method, report_document(report))
    assert parsed.observations
    assert validate_edge(query, parsed.observations[0].ioc, method, parsed.observations[0].evidence).accepted


def test_rsc_references_and_static_imported_dlls_do_not_become_commands_or_registry_values():
    report = synthetic_report()
    report["activity"]["process_activity"] = {"processes": [
        {"name": "$50", "command_line": "$4f", "api_calls": ["$undefined"]}],
        "all_imported_dlls": ["kernel32.dll"]}
    report["activity"]["registry_activity"]["keys_created"] = [{"key": "$4f"}]
    for output in ("command_api", "registry"):
        query = IOC("requested-name.bin", "filename")
        parsed = hybridanalysis.parse_document(query, get_method(f"hybridanalysis.filename_to_{output}"),
                                               report_document(report))
        assert not parsed.observations


@pytest.mark.parametrize("change", ["page_hash", "report_hash", "metadata_hash", "stage_hash"])
def test_report_identity_mismatch_is_rejected(change):
    report = synthetic_report()
    options = {}
    if change == "page_hash":
        options["sample_hash"] = "d" * 64
    elif change == "report_hash":
        report["sha256"] = "d" * 64
        options["sample_hash"] = SYNTHETIC_SHA256
    elif change == "metadata_hash":
        report["metadata"]["hashes"]["sha256"] = "d" * 64
    else:
        options["context"] = {"stage": "report", "sample_sha256": "d" * 64}
    with pytest.raises(LookupError) as failure:
        hybridanalysis.parse_document(IOC(SYNTHETIC_SHA256, "sha256"),
                                      get_method("hybridanalysis.sha256_to_command_api"),
                                      report_document(report, **options))
    assert failure.value.status == "invalid_response"


@pytest.mark.parametrize("stream", [
    '{"initialData":broken}',
    '{"initialData":{"schema_version":"1.0.17","sha256":"' + SYNTHETIC_SHA256 + '","sha256":"' + "d" * 64 + '"}}',
    '{"initialData":{"schema_version":"1.0.17"}}',
])
def test_malformed_or_duplicate_unified_json_is_not_silently_accepted(stream):
    with pytest.raises(LookupError) as failure:
        read_report(report_document(body=flight_html(stream=stream)))
    assert failure.value.status == "parse_error"


def test_unrelated_script_javascript_is_never_executed_as_report_data():
    body = '<script>self.__next_f.push([1, globalThis.thisMustNeverRun()]);</script>'
    with pytest.raises(LookupError) as failure:
        read_report(report_document(body=body))
    assert failure.value.status == "parse_error"


def test_captured_sample_does_not_invent_urls_from_its_command_line():
    query = IOC("search-input.bin", "filename")
    result = hybridanalysis.parse_document(query, get_method("hybridanalysis.filename_to_url"),
                                          report_document(captured_report()))
    assert not result.observations and result.reason == "url_unavailable"


def test_explicit_metadata_source_url_and_http_url_are_returned_as_source_values():
    report = synthetic_report()
    report["metadata"]["submissions"]["source_url"] = "https://github.com/python/cpython"
    query = IOC("search-input.bin", "filename")
    result = hybridanalysis.parse_document(query, get_method("hybridanalysis.filename_to_url"), report_document(report))
    assert {item.ioc.value for item in result.observations} == {RECORDED_URL, "https://github.com/python/cpython"}


def test_independent_method_correctness_rejects_wrong_field_output_or_runtime_input():
    query = IOC("ProviderFunction42", "command_api")
    method = get_method("hybridanalysis.command_api_to_registry")
    observation = hybridanalysis.parse_document(query, method, report_document()).observations[0]
    assert validate_edge(query, observation.ioc, method, observation.evidence).accepted
    for changes in ({"value": "HKCU\\Other"}, {"output_type": "filename"},
                    {"field": "initialData.metadata.file_info.file_name"},
                    {"runtime_command": "DifferentFunction"},
                    {"runtime_locator": "initialData.metadata.file_info.file_name"}):
        evidence = replace(observation.evidence, facts={**observation.evidence.facts, **changes})
        assert not validate_edge(query, observation.ioc, method, evidence).accepted


@pytest.mark.parametrize("status,reason", [("RUNNING", "report_processing"), ("ERROR", "report_incomplete")])
def test_incomplete_reports_retain_concrete_observations_but_mark_coverage(status, reason):
    report = synthetic_report()
    report["overall_status"] = status
    parsed = hybridanalysis.parse_document(IOC(SYNTHETIC_SHA256, "sha256"),
                                           get_method("hybridanalysis.sha256_to_command_api"), report_document(report))
    assert parsed.observations and not parsed.complete and parsed.reason == reason
