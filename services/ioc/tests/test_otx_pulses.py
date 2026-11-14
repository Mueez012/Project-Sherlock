"""Ordinary OTX discovery contracts and extraction/workflow boundaries.

End-to-end positives are synthetic offline replay data. Minimized actual browser
captures test source envelopes separately; provenance lives beside the fixtures.
"""
from dataclasses import replace
import json
from pathlib import Path
from unittest.mock import patch
from urllib.parse import parse_qs, urlencode, urlsplit

import pytest

from ioc_hunter import IOC, LookupClient, LookupError, get_method
from ioc_hunter.evidence import LookupRecord
from ioc_hunter.models import normalize
from ioc_hunter.providers import alienvault, parse_document, requests_for
from ioc_hunter.providers import otx_pulses
from ioc_hunter.storage import EvidenceStore
from ioc_hunter.transport import Document
from ioc_hunter.validation import validate_edge
from ioc_hunter.workflow.replay import ReplayTransport


HOST = "https://otx.alienvault.com"
PULSE_A, PULSE_B = "a" * 24, "b" * 24
EMAIL = "info@python.org"
OTHER_EMAIL = "contact@github.com"
FIXTURES = Path(__file__).parent / "fixtures" / "otx_pulses"


@pytest.fixture(autouse=True)
def forbid_external_requests():
    with patch("socket.socket.connect", side_effect=AssertionError("Offline OTX fixture attempted network")):
        yield


def selected(query, output):
    return get_method(f"alienvault.{query.type}_to_{output}")


def indicator(kind, value):
    return {"type": kind, "indicator": value, "created": "2026-11-10T00:00:00"}


def search_url(query, *, api=False, page=1):
    path = "/api/v1/search/pulses" if api else "/otxapi/pulses/"
    return HOST + path + "?" + urlencode({"q": normalize(query.type, query.value), "page": page})


def search_payload(*pulse_ids, counts=None, count=None, next_value=None):
    rows = [{"id": pulse_id} for pulse_id in pulse_ids]
    if counts is not None:
        for row, value in zip(rows, counts):
            row["indicator_type_counts"] = value
    return {"results": rows, "count": len(rows) if count is None else count,
            "next": next_value, "previous": None}


def entry(request, response_url, data, *, status=None):
    result = {"source": "alienvault", "request_url": request.url, "response_url": response_url,
              "operation": request.operation, "format": "json", "fixture_provenance": "synthetic"}
    if status:
        result.update(error_status=status, error="Synthetic ordinary OTX source failure")
    else:
        result["body"] = json.dumps(data)
    return result


def search_entry(query, output, payload, *, api_key="", api=False, response_url=None, status=None):
    method = selected(query, output)
    routes = requests_for(query, method, api_key)
    request = routes[-1 if api else 0][1]
    return entry(request, response_url or search_url(query, api=api), payload, status=status)


def pulse_entry(query, output, pulse_id=PULSE_A, *, rows=(), api_key="", api=False,
                count=None, next_value=None, response_pulse=None, status=None):
    method = replace(selected(query, output), input_type="pulse", operation="pulse_indicators")
    routes = requests_for(IOC(pulse_id, "pulse"), method, api_key)
    request = routes[-1 if api else 0][1]
    actual = response_pulse or pulse_id
    response = HOST + (f"/api/v1/pulses/{actual}/indicators" if api else
                       f"/otxapi/pulses/{actual}/indicators/?sort=-created&limit=10&page=1")
    data = {"results": list(rows), "count": len(rows) if count is None else count,
            "next": next_value, "previous": None}
    return entry(request, response, data, status=status)


def client_for(tmp_path, *documents, api_keys=None, **limits):
    manifest = tmp_path / "replay.json"
    manifest.write_text(json.dumps({"version": 1, "provenance": "synthetic",
                                    "documents": documents}), encoding="utf-8")
    transport = ReplayTransport(manifest)
    client = LookupClient(store=EvidenceStore(tmp_path / "store"), browser=transport, http=transport,
                          api_keys={} if api_keys is None else api_keys,
                          cache_ttl=limits.pop("cache_ttl", 0), interval=0, **limits)
    return client, transport


@pytest.mark.parametrize("query,output,rows,expected", [
    (IOC(EMAIL, "email"), "domain", [indicator("domain", "python.org"), indicator("hostname", "www.python.org")],
     {"python.org", "www.python.org"}),
    (IOC(EMAIL, "email"), "email", [indicator("email", EMAIL), indicator("email", OTHER_EMAIL)], {OTHER_EMAIL}),
    (IOC("US", "geo_location"), "ipv4", [indicator("IPv4", "192.0.2.10")], {"192.0.2.10"}),
    (IOC("8443", "port"), "protocol", [indicator("URL", "https://www.python.org:8443/path")], {"https"}),
    (IOC("http", "protocol"), "port", [indicator("URL", "http://www.python.org:8080/path")], {"8080"}),
])
def test_all_five_methods_use_shared_bounded_pipeline_with_synthetic_source_rows(tmp_path, query, output, rows, expected):
    client, transport = client_for(tmp_path, search_entry(query, output, search_payload(PULSE_A)),
                                   pulse_entry(query, output, rows=rows))
    record = client.lookup_detailed(query, selected(query, output).id)
    assert {item.value for item in record.outputs} == expected
    assert record.status == "ok" and record.complete and not record.cache_hit
    assert len(transport.requests) == len(record.responses) == 2
    assert [request.operation for request in transport.requests] == ["pulse_search", "pulse_indicators"]
    assert all(evidence.source == "alienvault" and evidence.query_value == query.value
               and evidence.operation == "pulse_search" for evidence in record.evidence)
    assert LookupRecord.from_dict(client.store.get_record(record.id)).to_dict() == record.to_dict()
    assert all(item.type != "pulse" for item in record.outputs)


def test_actual_captured_search_envelope_and_indicator_rows_keep_partial_coverage():
    query = IOC("8080", "port")
    payload = (FIXTURES / "search_8080_captured_minimized.json").read_text(encoding="utf-8")
    document = Document(search_url(query), payload, "json", diagnostics={
        "request_context": {"stage": "search", "search_text": "8080"}})
    page = parse_document(query, selected(query, "protocol"), document)
    assert not page.observations and page.next_url
    # Both actual retained references explicitly have no URL indicators. The
    # port-to-protocol path can skip them without spending report-read budget.
    assert not page.followups

    # This actual pulse-stage fixture establishes typed domain extraction, not
    # that the synthetic email input found this pulse in a live search.
    pulse_id = "69c08867316c564ade394c69"
    query = IOC(EMAIL, "email")
    document = Document(HOST + f"/otxapi/pulses/{pulse_id}/indicators/?page=1",
                        (FIXTURES / "indicators_captured_minimized.json").read_text(encoding="utf-8"),
                        "json", diagnostics={"request_context": {
                            "stage": "indicators", "pulse_id": pulse_id, "search_text": EMAIL}})
    page = parse_document(query, selected(query, "domain"), document)
    assert {item.ioc.value for item in page.observations} == {"ssmp.tech", "mrking100062.com"}
    assert all(validate_edge(query, item.ioc, selected(query, "domain"), item.evidence).accepted
               for item in page.observations)
    assert page.next_url or not page.complete


def test_typed_rows_only_no_description_url_or_email_mailbox_derivation(tmp_path):
    query = IOC(EMAIL, "email")
    rows = [indicator("domain", "github.com"), indicator("hostname", "www.github.com"),
            indicator("email", OTHER_EMAIL), indicator("URL", "https://www.python.org/"),
            {**indicator("text", "python.org"), "description": "phishing@python.org 192.0.2.20"},
            indicator("domain", "not a domain")]
    client, _ = client_for(tmp_path, search_entry(query, "domain", search_payload(PULSE_A)),
                           pulse_entry(query, "domain", rows=rows))
    record = client.lookup_detailed(query, selected(query, "domain").id)
    assert {item.value for item in record.outputs} == {"github.com", "www.github.com"}
    assert "python.org" not in {item.value for item in record.outputs}


@pytest.mark.parametrize("query,output,rows,expected", [
    (IOC("8443", "port"), "protocol", [
        indicator("URL", "https://www.python.org:8443/path"),
        indicator("URL", "http://www.python.org:8443/path"),
        indicator("URL", "ftp://www.python.org:8443/path"),
        indicator("URL", "https://www.python.org/"),
        indicator("URL", "https://www.python.org:443/path"),
        indicator("URL", "https://name:password@www.python.org:8443/")], {"https", "http", "ftp"}),
    (IOC("https", "protocol"), "port", [
        indicator("URL", "https://www.python.org:8443/path"),
        indicator("URL", "https://www.python.org:443/path"),
        indicator("URL", "https://www.python.org/"),
        indicator("URL", "http://www.python.org:8080/path"),
        indicator("URL", "https://www.python.org:70000/path")], {"8443", "443"}),
])
def test_url_components_require_matching_explicit_port_or_scheme_without_default_tables(tmp_path, query, output, rows, expected):
    client, _ = client_for(tmp_path, search_entry(query, output, search_payload(PULSE_A)),
                           pulse_entry(query, output, rows=rows))
    record = client.lookup_detailed(query, selected(query, output).id)
    assert {item.value for item in record.outputs} == expected
    assert all(evidence.facts["explicit_port"] and evidence.facts["url"] for evidence in record.evidence)
    assert "tcp" not in {item.value for item in record.outputs}


@pytest.mark.parametrize("protocol", ["tcp", "udp", "icmp", "tls"])
def test_unsupported_transport_protocol_subset_fails_before_any_source_request(tmp_path, protocol):
    client, transport = client_for(tmp_path)
    with pytest.raises(LookupError) as failure:
        client.lookup(IOC(protocol, "protocol"), "alienvault.protocol_to_port")
    assert failure.value.status == "unsupported_input"
    assert not transport.requests
    assert client.store.get_record(failure.value.lookup_id)["status"] == "unsupported_input"


def test_configured_api_fallback_survives_search_and_pulse_steps_without_secret_receipts(tmp_path):
    query = IOC(EMAIL, "email")
    key = "synthetic-configured-key"
    client, transport = client_for(
        tmp_path,
        search_entry(query, "domain", {}, status="not_found"),
        search_entry(query, "domain", search_payload(PULSE_A), api=True, api_key=key),
        pulse_entry(query, "domain", status="not_found"),
        pulse_entry(query, "domain", rows=[indicator("domain", "python.org")], api=True, api_key=key),
        api_keys={"alienvault": key})
    record = client.lookup_detailed(query, selected(query, "domain").id)
    assert [item.value for item in record.outputs] == ["python.org"]
    assert [bool(request.headers) for request in transport.requests] == [False, True, False, True]
    assert key not in json.dumps(record.to_dict())
    assert key not in " ".join(json.dumps(client.store.get_snapshot(ref["snapshot_id"])) for ref in record.responses)


def test_known_zero_needed_indicator_counts_skip_irrelevant_pulses_and_missing_counts_still_read(tmp_path):
    query = IOC(EMAIL, "email")
    data = search_payload(PULSE_A, PULSE_B, counts=[{"URL": 10}, None])
    data["results"][1].pop("indicator_type_counts")
    client, transport = client_for(tmp_path, search_entry(query, "domain", data),
                                   pulse_entry(query, "domain", PULSE_B, rows=[indicator("domain", "github.com")]))
    record = client.lookup_detailed(query, selected(query, "domain").id)
    assert [item.value for item in record.outputs] == ["github.com"]
    assert len(transport.requests) == 2 and PULSE_B in transport.requests[1].url


def test_followup_limit_and_duplicate_pulse_references_keep_useful_outputs_partial(tmp_path):
    query = IOC(EMAIL, "email")
    client, transport = client_for(tmp_path, search_entry(query, "domain", search_payload(PULSE_A, PULSE_A, PULSE_B)),
                                   pulse_entry(query, "domain", rows=[indicator("domain", "python.org")]), max_followups=1)
    record = client.lookup_detailed(query, selected(query, "domain").id)
    assert [item.value for item in record.outputs] == ["python.org"]
    assert record.status == "partial" and "followup_limit" in record.partial_reasons
    assert len(transport.requests) == 2


@pytest.mark.parametrize("stage,data,expected", [
    ("search", {"results": [], "count": 0, "next": None}, "empty"),
    ("indicators", {"results": [], "count": 0, "next": None}, "empty"),
    ("search", {"results": [], "count": 100, "next": None}, "partial"),
])
def test_completed_empty_and_capped_responses_have_distinct_receipts(tmp_path, stage, data, expected):
    query = IOC(EMAIL, "email")
    documents = [search_entry(query, "domain", data if stage == "search" else search_payload(PULSE_A))]
    if stage == "indicators":
        documents.append(pulse_entry(query, "domain", rows=[]))
    client, _ = client_for(tmp_path, *documents)
    record = client.lookup_detailed(query, selected(query, "domain").id)
    assert record.outputs == [] and record.status == expected
    if expected == "partial":
        assert "pulse_results_capped" in record.partial_reasons


def test_browser_pagination_is_partial_without_a_verified_next_control_but_required_pulses_still_read(tmp_path):
    query = IOC(EMAIL, "email")
    data = search_payload(PULSE_A, count=2, next_value=search_url(query, page=2))
    client, transport = client_for(tmp_path, search_entry(query, "domain", data),
                                   pulse_entry(query, "domain", rows=[indicator("domain", "github.com")]), max_pages=2)
    record = client.lookup_detailed(query, selected(query, "domain").id)
    assert [item.value for item in record.outputs] == ["github.com"]
    assert record.status == "partial" and "browser_pagination_not_verified" in record.partial_reasons
    assert len(transport.requests) == 2


@pytest.mark.parametrize("mutation", ["query", "host", "context", "pulse"])
def test_query_source_and_pulse_mismatches_are_failures_not_empty_answers(tmp_path, mutation):
    query = IOC(EMAIL, "email")
    first = search_entry(query, "domain", search_payload(PULSE_A))
    second = pulse_entry(query, "domain", rows=[indicator("domain", "python.org")])
    if mutation == "query":
        first["response_url"] = search_url(IOC(OTHER_EMAIL, "email"))
    elif mutation == "host":
        first["response_url"] = "https://www.python.org/"
    elif mutation == "context":
        document = Document(search_url(query), json.dumps(search_payload(PULSE_A)), "json",
                            diagnostics={"request_context": {"stage": "search", "search_text": OTHER_EMAIL}})
        with pytest.raises(LookupError) as failure:
            parse_document(query, selected(query, "domain"), document)
        assert failure.value.status == "invalid_response"
        return
    else:
        second["response_url"] = HOST + f"/otxapi/pulses/{PULSE_B}/indicators/"
    client, _ = client_for(tmp_path, first, second)
    if mutation == "pulse":
        record = client.lookup_detailed(query, selected(query, "domain").id)
        assert record.status == "partial" and record.outcome_reason == "followup_failed"
        assert not record.outputs
    else:
        with pytest.raises(LookupError) as failure:
            client.lookup(query, selected(query, "domain").id)
        assert failure.value.status == "invalid_response"


@pytest.mark.parametrize("data", [
    {}, {"results": {}}, {"results": ["not an object"]},
    {"results": [{"id": "not-a-pulse-reference"}]},
])
def test_malformed_discovery_envelopes_raise_parse_errors(tmp_path, data):
    query = IOC(EMAIL, "email")
    client, _ = client_for(tmp_path, search_entry(query, "domain", data))
    with pytest.raises(LookupError) as failure:
        client.lookup(query, selected(query, "domain").id)
    assert failure.value.status == "parse_error"


@pytest.mark.parametrize("rows", [None, {}, ["bad row"], [{"type": "domain"}], [{"type": "domain", "indicator": 42}]])
def test_malformed_required_pulse_data_remains_partial_with_explicit_failure(rows, tmp_path):
    query = IOC(EMAIL, "email")
    first = search_entry(query, "domain", search_payload(PULSE_A))
    second = pulse_entry(query, "domain", rows=[])
    second["body"] = json.dumps({"results": rows})
    client, _ = client_for(tmp_path, first, second)
    record = client.lookup_detailed(query, selected(query, "domain").id)
    assert not record.outputs and record.status == "partial"
    assert "followup_failed:parse_error" in record.partial_reasons


@pytest.mark.parametrize("target", ["https://www.python.org/", HOST + "/otxapi/other/"])
def test_untrusted_pagination_is_rejected(target, tmp_path):
    query = IOC(EMAIL, "email")
    client, _ = client_for(tmp_path, search_entry(query, "domain", search_payload(PULSE_A, next_value=target)))
    with pytest.raises(LookupError) as failure:
        client.lookup(query, selected(query, "domain").id)
    assert failure.value.status == "unsafe_pagination"


def test_independent_method_guard_rejects_inconsistent_values_and_url_fields(tmp_path):
    query = IOC("8443", "port")
    method = selected(query, "protocol")
    client, _ = client_for(tmp_path, search_entry(query, "protocol", search_payload(PULSE_A)),
                           pulse_entry(query, "protocol", rows=[indicator("URL", "https://www.python.org:8443/path")]))
    record = client.lookup_detailed(query, method.id)
    evidence, output = record.evidence[0], record.outputs[0]
    assert validate_edge(query, output, method, evidence).accepted
    for changes in ({"search_text": "443"}, {"value": "http"}, {"pulse_id": "z" * 24},
                    {"explicit_port": "443"}, {"scheme": "http"},
                    {"indicator": "https://www.python.org/path"}):
        altered = replace(evidence, facts={**evidence.facts, **changes})
        assert not validate_edge(query, output, method, altered).accepted


def test_internal_pulse_navigation_is_not_a_new_public_ioc_method():
    query = IOC(EMAIL, "email")
    method = selected(query, "domain")
    internal = replace(method, input_type="pulse", operation="pulse_indicators")
    for value in ("invalid", "z" * 24, "../pulse"):
        with pytest.raises(LookupError) as failure:
            alienvault.requests_for(IOC(value, "pulse"), internal)
        assert failure.value.status == "invalid_request"
    with pytest.raises(ValueError):
        normalize("pulse", PULSE_A)
