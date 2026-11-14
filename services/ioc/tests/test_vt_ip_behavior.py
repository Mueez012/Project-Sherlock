"""Offline VT IP discovery/behavior integration; never fresh live requests.

Most responses below are synthetic; the network-contract regression uses a
minimized actual report-field capture with synthetic file discovery.
The real ReplayTransport fails closed for any request missing from the manifest.
These tests are prepared separately from their execution.
"""
from dataclasses import replace
import json
from pathlib import Path
from unittest.mock import patch

import pytest

from ioc_hunter import IOC, LookupClient, LookupError, get_method
from ioc_hunter.evidence import LookupRecord
from ioc_hunter.providers import parse_document
from ioc_hunter.storage import EvidenceStore
from ioc_hunter.transport import Document
from ioc_hunter.validation import validate_edge
from ioc_hunter.workflow.replay import ReplayTransport


QUERY_IP = "198.51.100.10"
OTHER_IP = "198.51.100.11"
PEER_IP = "203.0.113.15"
SECOND_PEER = "203.0.113.16"
THIRD_PEER = "203.0.113.17"
FILE_A = "a" * 64
FILE_B = "b" * 64
COMMAND_METHOD = "virustotal.ipv4_to_command_api"
NETWORK_METHOD = "virustotal.ipv4_to_ipv4"
IP_PAGE = f"https://www.virustotal.com/gui/ip-address/{QUERY_IP}/relations"
IP_RESPONSE = f"https://www.virustotal.com/ui/ip_addresses/{QUERY_IP}/communicating_files"
IP_API = f"https://www.virustotal.com/api/v3/ip_addresses/{QUERY_IP}/communicating_files"


@pytest.fixture(autouse=True)
def forbid_external_requests():
    with patch("socket.socket.connect", side_effect=AssertionError("Offline VT fixture attempted network")):
        yield


def entry(request_url, response_url, data, *, operation="ip_file_behavior"):
    return {"source": "virustotal", "request_url": request_url,
            "response_url": response_url, "operation": operation, "format": "json",
            "body": json.dumps(data), "fixture_provenance": "synthetic"}


def discovery(*file_hashes, response_ip=QUERY_IP, rows=None, next_url="", api=False):
    data = {"data": ([{"id": value, "type": "file", "attributes": {"sha256": value}}
                      for value in file_hashes] if rows is None else rows)}
    if next_url:
        data["links"] = {"next": next_url}
    response = f"https://www.virustotal.com/ui/ip_addresses/{response_ip}/communicating_files"
    return entry(IP_API if api else IP_PAGE,
                 IP_API if api and response_ip == QUERY_IP else response, data)


def behavior(file_hash=FILE_A, *, attributes=None, report_hash=None, api=False):
    attributes = {"command_executions": ["cmd.exe /c whoami"]} if attributes is None else attributes
    request_url = (f"https://www.virustotal.com/api/v3/files/{file_hash}/behaviour_summary" if api else
                   f"https://www.virustotal.com/gui/file/{file_hash}/behavior")
    response_url = (request_url if api else
                    f"https://www.virustotal.com/ui/files/{file_hash}/behaviours")
    data = {"data": attributes} if api else {"data": [{
        "id": (report_hash or file_hash) + "_synthetic-sandbox", "type": "file_behaviour",
        "attributes": attributes,
    }]}
    return entry(request_url, response_url, data, operation="file_behavior")


def failure(request_url, *, operation, status="not_found"):
    return {"source": "virustotal", "request_url": request_url, "operation": operation,
            "error_status": status, "error": "Synthetic offline provider failure",
            "fixture_provenance": "synthetic"}


def client_for(tmp_path, *documents, api_keys=None, provenance="synthetic", **limits):
    manifest = tmp_path / "replay.json"
    manifest.write_text(json.dumps({"version": 1, "provenance": provenance,
                                    "documents": documents}), encoding="utf-8")
    replay = ReplayTransport(manifest)
    client = LookupClient(store=EvidenceStore(tmp_path / "store"), browser=replay, http=replay,
                          api_keys={} if api_keys is None else api_keys,
                          cache_ttl=0, interval=0, **limits)
    return client, replay


def test_ip_command_method_replays_discovery_and_shared_behavior_without_actor_scoring(tmp_path):
    client, replay = client_for(
        tmp_path, discovery(FILE_A, FILE_B),
        behavior(attributes={"command_executions": ["cmd.exe /c whoami"],
                             "calls_highlighted": ["GetTickCount"]}),
        behavior(FILE_B, attributes={"command_executions": ["cmd.exe /c whoami"]}))
    query = IOC(QUERY_IP, "ipv4", ["Original CTI passage"], "synthetic report")
    receipt = client.lookup_detailed(query, COMMAND_METHOD)
    assert [(ioc.type, ioc.value) for ioc in receipt.outputs] == [
        ("command_api", "cmd.exe /c whoami"), ("command_api", "GetTickCount")]
    assert receipt.status == "ok" and receipt.complete and not receipt.cache_hit
    assert len(receipt.accepted) == 3 and not receipt.rejected
    assert len(replay.requests) == len(receipt.responses) == 3
    assert [request.operation for request in replay.requests] == [
        "ip_file_behavior", "file_behavior", "file_behavior"]
    assert all(not request.headers for request in replay.requests)
    assert all(evidence.fact_type == "ip_file_behavior" for evidence in receipt.evidence)
    assert {evidence.facts["file_hash"] for evidence in receipt.evidence} == {FILE_A, FILE_B}
    assert all(evidence.query_value == QUERY_IP and evidence.facts["discovery_ip"] == QUERY_IP
               for evidence in receipt.evidence)
    assert query.context == ["Original CTI passage"]
    assert LookupRecord.from_dict(client.store.get_record(receipt.id)).to_dict() == receipt.to_dict()


def test_ip_network_method_reads_structured_fields_deduplicates_and_rejects_query_echo(tmp_path):
    client, replay = client_for(tmp_path, discovery(FILE_A), behavior(attributes={
        "ip_traffic": [{"destination_ip": PEER_IP}, {"destination_ip": QUERY_IP},
                       {"source_ip": PEER_IP}],
        "dns_lookups": [{"resolved_ips": [SECOND_PEER, "2001:db8::1"]}],
        "http_conversations": [{"remote_ip": PEER_IP}],
        "ids_alerts": [{"alert_context": {"src_ip": THIRD_PEER, "dest_ip": PEER_IP}}],
        "command_executions": ["203.0.113.99"],
    }))
    receipt = client.lookup_detailed(IOC(QUERY_IP, "ipv4"), NETWORK_METHOD)
    assert {(ioc.type, ioc.value) for ioc in receipt.outputs} == {
        ("ipv4", PEER_IP), ("ipv4", SECOND_PEER), ("ipv4", THIRD_PEER)}
    assert receipt.complete and receipt.status == "ok" and not receipt.cache_hit
    assert [row["reason"] for row in receipt.rejected] == ["query_echo"]
    assert all(evidence.fact_type == "ip_file_network" for evidence in receipt.evidence)
    assert len(replay.requests) == 2


def test_captured_network_fields_pass_through_real_discovery_and_receipt_pipeline(tmp_path):
    """Actual network field values; communicating-file discovery stays synthetic."""
    fixture = Path(__file__).parent / "fixtures" / "vt_file_network_ui_captured.json"
    captured = json.loads(fixture.read_text(encoding="utf-8"))
    sample_hash = "f55fe457929044e4c4cdc62b4ad0a4955bd2faac2b642318649beede66086eb4"
    response = entry(f"https://www.virustotal.com/gui/file/{sample_hash}/behavior",
                     f"https://www.virustotal.com/ui/files/{sample_hash}/behaviours",
                     captured, operation="file_behavior")
    response["fixture_provenance"] = "captured_minimized_network_fields"
    client, replay = client_for(tmp_path, discovery(sample_hash), response,
                                provenance="mixed synthetic discovery and captured report fields")
    receipt = client.lookup_detailed(IOC(QUERY_IP, "ipv4"), NETWORK_METHOD)
    values = {ioc.value for ioc in receipt.outputs}
    assert {"204.79.197.203", "20.99.184.37", "23.216.147.64", "104.125.89.159"} <= values
    assert all(ioc.type == "ipv4" and ":" not in ioc.value for ioc in receipt.outputs)
    assert len(values) == len(receipt.outputs)
    assert receipt.status == "ok" and receipt.complete and not receipt.cache_hit
    assert len(replay.requests) == len(receipt.responses) == 2
    assert all(evidence.facts["file_hash"] == sample_hash for evidence in receipt.evidence)
    assert {evidence.facts["field"] for evidence in receipt.evidence} == {
        "ip_traffic.destination_ip", "dns_lookups.resolved_ips"}


def test_configured_api_fallback_is_resolved_for_discovery_and_child_without_leaking_key(tmp_path):
    browser_file = f"https://www.virustotal.com/gui/file/{FILE_A}/behavior"
    client, replay = client_for(
        tmp_path, failure(IP_PAGE, operation="ip_file_behavior"), discovery(FILE_A, api=True),
        failure(browser_file, operation="file_behavior"), behavior(api=True),
        api_keys={"virustotal": "synthetic-test-key"})
    receipt = client.lookup_detailed(IOC(QUERY_IP, "ipv4"), COMMAND_METHOD)
    assert [ioc.value for ioc in receipt.outputs] == ["cmd.exe /c whoami"]
    assert receipt.complete and receipt.status == "ok"
    assert [request.url for request in replay.requests] == [
        IP_PAGE, IP_API, browser_file,
        f"https://www.virustotal.com/api/v3/files/{FILE_A}/behaviour_summary"]
    assert replay.requests[1].headers == replay.requests[3].headers == {"x-apikey": "synthetic-test-key"}
    assert replay.requests[3].context == {"stage": "file_behavior", "file_hash": FILE_A,
                                          "query_ip": QUERY_IP}
    stored = client.store.get_record(receipt.id)
    snapshots = [client.store.get_snapshot(row["snapshot_id"]) for row in stored["responses"]]
    assert "synthetic-test-key" not in json.dumps({"receipt": stored, "snapshots": snapshots})


def test_discovery_response_for_another_ip_fails_before_child_acquisition(tmp_path):
    client, replay = client_for(tmp_path, discovery(FILE_A, response_ip=OTHER_IP))
    with pytest.raises(LookupError) as failure_info:
        client.lookup(IOC(QUERY_IP, "ipv4"), COMMAND_METHOD)
    assert failure_info.value.status == "invalid_response"
    receipt = client.store.get_record(failure_info.value.lookup_id)
    assert receipt["status"] == "invalid_response" and not receipt["outputs"]
    assert len(replay.requests) == 1 and receipt["responses"]


@pytest.mark.parametrize("rows", [
    {}, [{"id": "not-a-hash", "type": "file"}],
    [{"id": FILE_A, "type": "domain"}], [None],
])
def test_malformed_discovery_is_an_error_instead_of_a_completed_empty_lookup(tmp_path, rows):
    client, replay = client_for(tmp_path, discovery(rows=rows))
    with pytest.raises(LookupError) as failure_info:
        client.lookup(IOC(QUERY_IP, "ipv4"), COMMAND_METHOD)
    assert failure_info.value.status == "parse_error"
    receipt = client.store.get_record(failure_info.value.lookup_id)
    assert receipt["status"] == "parse_error" and receipt["responses"] and not receipt["outputs"]
    assert len(replay.requests) == 1


def test_behavior_for_a_different_discovered_hash_is_retained_as_partial_failure(tmp_path):
    client, replay = client_for(tmp_path, discovery(FILE_A), behavior(report_hash=FILE_B))
    receipt = client.lookup_detailed(IOC(QUERY_IP, "ipv4"), COMMAND_METHOD)
    assert receipt.status == "partial" and not receipt.complete and not receipt.outputs
    assert "followup_failed:invalid_response" in receipt.partial_reasons
    assert len(replay.requests) == len(receipt.responses) == 2


def test_later_malformed_behavior_preserves_already_extracted_commands(tmp_path):
    client, replay = client_for(tmp_path, discovery(FILE_A, FILE_B), behavior(),
                                behavior(FILE_B, attributes={"command_executions": "invalid list"}))
    receipt = client.lookup_detailed(IOC(QUERY_IP, "ipv4"), COMMAND_METHOD)
    assert [ioc.value for ioc in receipt.outputs] == ["cmd.exe /c whoami"]
    assert receipt.status == "partial" and not receipt.complete
    assert "followup_failed:parse_error" in receipt.partial_reasons
    assert receipt.outcome_reason == "followup_failed"
    assert len(replay.requests) == len(receipt.responses) == 3


@pytest.mark.parametrize("attributes", [
    {"ip_traffic": "invalid list"},
    {"ip_traffic": ["invalid record"]},
    {"dns_lookups": [{"resolved_ips": "invalid list"}]},
    {"ids_alerts": [{"alert_context": "invalid context"}]},
])
def test_malformed_network_fields_remain_partial_failures_instead_of_empty_success(tmp_path, attributes):
    client, replay = client_for(tmp_path, discovery(FILE_A), behavior(attributes=attributes))
    receipt = client.lookup_detailed(IOC(QUERY_IP, "ipv4"), NETWORK_METHOD)
    assert receipt.status == "partial" and not receipt.complete and not receipt.outputs
    assert "followup_failed:parse_error" in receipt.partial_reasons
    assert len(replay.requests) == len(receipt.responses) == 2


@pytest.mark.parametrize("method", [COMMAND_METHOD, NETWORK_METHOD])
def test_completed_empty_discovery_does_not_fabricate_a_behavior_read(tmp_path, method):
    client, replay = client_for(tmp_path, discovery())
    receipt = client.lookup_detailed(IOC(QUERY_IP, "ipv4"), method)
    assert receipt.status == "empty" and receipt.complete and not receipt.outputs
    assert not receipt.cache_hit and len(replay.requests) == 1


def test_followup_limit_bounds_actual_file_reads_and_marks_retained_results_partial(tmp_path):
    client, replay = client_for(tmp_path, discovery(FILE_A, FILE_B), behavior(), max_followups=1)
    receipt = client.lookup_detailed(IOC(QUERY_IP, "ipv4"), COMMAND_METHOD)
    assert [ioc.value for ioc in receipt.outputs] == ["cmd.exe /c whoami"]
    assert receipt.status == "partial" and not receipt.complete
    assert "followup_limit" in receipt.partial_reasons
    assert len(replay.requests) == 2


def test_unverified_browser_pagination_retains_first_page_file_results_as_partial(tmp_path):
    client, replay = client_for(
        tmp_path, discovery(FILE_A, next_url=IP_RESPONSE + "?cursor=synthetic-next"), behavior())
    receipt = client.lookup_detailed(IOC(QUERY_IP, "ipv4"), COMMAND_METHOD)
    assert [ioc.value for ioc in receipt.outputs] == ["cmd.exe /c whoami"]
    assert not receipt.complete and receipt.status == "partial"
    assert "browser_pagination_not_verified" in receipt.partial_reasons
    assert len(replay.requests) == 2


def test_method_correctness_checks_discovery_input_output_and_declared_behavior_field():
    method = get_method(COMMAND_METHOD)
    query = IOC(QUERY_IP, "ipv4")
    raw = behavior()
    document = Document(raw["response_url"], raw["body"], "json", "replay", diagnostics={
        "request_context": {"stage": "file_behavior", "file_hash": FILE_A, "query_ip": QUERY_IP}})
    observation = parse_document(query, method, document).observations[0]
    assert validate_edge(query, observation.ioc, method, observation.evidence).accepted
    for changes in ({"discovery_ip": OTHER_IP}, {"value": "different-command"},
                    {"field": "unrelated_report_text"}, {"file_hash": "invalid"}):
        wrong = replace(observation.evidence, facts={**observation.evidence.facts, **changes})
        assert not validate_edge(query, observation.ioc, method, wrong).accepted
