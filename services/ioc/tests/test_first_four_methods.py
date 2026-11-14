"""Offline first-four integration through the real lookup/workflow boundaries."""
from dataclasses import replace
from hashlib import sha256
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
from ioc_hunter.workflow.runner import build_runner


URL = "https://download.sysinternals.com/files/ProcessExplorer.zip"
URL_ID = sha256(URL.encode()).hexdigest()
URL_METHOD = "virustotal.url_to_filename"
HASHES = {"md5": "a" * 32, "sha1": "b" * 40, "sha256": "c" * 64}


def url_document(headers=None, *, omit_headers=False, url=URL):
    attributes = {"url": url}
    if not omit_headers:
        attributes["last_http_response_headers"] = {} if headers is None else headers
    return Document(f"https://www.virustotal.com/ui/urls/{URL_ID}",
                    json.dumps({"data": {"id": URL_ID, "attributes": attributes}}), "json")


class OfflineTransport:
    offline = True

    def __init__(self, *documents):
        self.documents = list(documents)
        self.requests = []

    def fetch(self, request):
        self.requests.append(request)
        if not self.documents:
            raise AssertionError("Unexpected acquisition")
        return self.documents.pop(0)


def test_url_filename_uses_existing_url_details_request_cache_and_receipt(tmp_path):
    raw = "attachment; filename=plain.exe; filename*=UTF-8''r%C3%A9sum%C3%A9.exe"
    transport = OfflineTransport(url_document({"Content-Disposition": raw}))
    client = LookupClient(store=EvidenceStore(tmp_path), browser=transport, api_keys={}, interval=0)
    query = IOC(URL, "url", ["Original report passage"], "cti report")
    assert [ioc.value for ioc in client.lookup(query, "virustotal.url_to_domain")] == ["download.sysinternals.com"]
    record = client.lookup_detailed(query, URL_METHOD)
    assert len(transport.requests) == 1
    assert record.cache_hit
    assert [(ioc.type, ioc.value) for ioc in record.outputs] == [("filename", "résumé.exe")]
    assert record.accepted[0]["ontology_label"] == "parse/own"
    assert record.evidence[0].facts["header"] == raw
    assert record.evidence[0].locator.endswith('last_http_response_headers["Content-Disposition"]')
    assert query.context == ["Original report passage"]
    assert LookupRecord.from_dict(client.store.get_record(record.id)).to_dict() == record.to_dict()


@pytest.mark.parametrize("document", [
    url_document(omit_headers=True), url_document({}),
    url_document({"Content-Disposition": "inline"}),
    url_document({"Content-Type": "application/octet-stream"}),
])
def test_url_without_explicit_filename_is_completed_empty(tmp_path, document):
    transport = OfflineTransport(document)
    client = LookupClient(store=EvidenceStore(tmp_path), browser=transport, api_keys={})
    record = client.lookup_detailed(IOC(URL, "url"), URL_METHOD)
    assert record.outputs == []
    assert record.status == "empty"
    assert record.outcome_reason == "filename_unavailable"
    assert record.responses
    assert len(transport.requests) == 1


@pytest.mark.parametrize("document", [
    url_document({"Content-Disposition": 'attachment; filename="../bad.exe"'}),
    url_document({"Content-Disposition": "attachment; filename*=UTF-8''broken%ZZ.exe"}),
    url_document({"Content-Disposition": ["attachment; filename=one.exe"]}),
    url_document({"Content-Disposition": "attachment; filename=a.exe"}, url="https://www.python.org/"),
])
def test_wrong_identity_or_malformed_filename_response_retains_error(tmp_path, document):
    client = LookupClient(store=EvidenceStore(tmp_path), browser=OfflineTransport(document), api_keys={})
    with pytest.raises(LookupError) as failure:
        client.lookup(IOC(URL, "url"), URL_METHOD)
    assert failure.value.status == "parse_error"
    receipt = client.store.get_record(failure.value.lookup_id)
    assert receipt["status"] == "parse_error"
    assert receipt["responses"]
    assert not receipt["outputs"]


def test_duplicate_raw_json_header_keys_are_not_silently_collapsed(tmp_path):
    body = ('{"data":{"id":"' + URL_ID + '","attributes":{"url":"' + URL + '",'
            '"last_http_response_headers":{"Content-Disposition":"attachment; filename=a.exe",'
            '"Content-Disposition":"attachment; filename=b.exe"}}}}')
    document = Document(f"https://www.virustotal.com/ui/urls/{URL_ID}", body, "json")
    client = LookupClient(store=EvidenceStore(tmp_path), browser=OfflineTransport(document), api_keys={})
    with pytest.raises(LookupError) as failure:
        client.lookup(IOC(URL, "url"), URL_METHOD)
    assert failure.value.status == "parse_error"


def test_filename_method_correctness_checks_exact_output_and_query():
    method = get_method(URL_METHOD)
    query = IOC(URL, "url")
    observation = parse_document(query, method,
                                 url_document({"Content-Disposition": "attachment; filename=payload.exe"})).observations[0]
    assert validate_edge(query, observation.ioc, method, observation.evidence).accepted
    wrong = replace(observation.evidence, facts={**observation.evidence.facts, "filename": "other.exe"})
    assert not validate_edge(query, observation.ioc, method, wrong).accepted
    wrong = replace(observation.evidence, query_value="https://www.python.org/")
    assert not validate_edge(query, observation.ioc, method, wrong).accepted


def test_captured_sysinternals_report_without_disposition_is_not_guessed(tmp_path):
    body = (Path(__file__).parent / "fixtures" / "vt_url_filename_sysinternals_captured.json").read_text(
        encoding="utf-8")
    data = json.loads(body)["data"]
    query = IOC(data["attributes"]["url"], "url")
    document = Document(f"https://www.virustotal.com/ui/urls/{data['id']}", body, "json")
    client = LookupClient(store=EvidenceStore(tmp_path), browser=OfflineTransport(document), api_keys={})
    receipt = client.lookup_detailed(query, URL_METHOD)
    assert receipt.status == "empty"
    assert receipt.outcome_reason == "filename_unavailable"
    assert receipt.outputs == []  # The URL path's ProcessExplorer.zip is not a header filename.


@pytest.mark.parametrize("kind,value", [
    ("md5", "c438b19e627b1c1e9cb8970f2fe5f929"),
    ("sha1", "f9e903e70baf8a3cece4bf554ce3d6fae63c1805"),
    ("sha256", "f55fe457929044e4c4cdc62b4ad0a4955bd2faac2b642318649beede66086eb4"),
])
def test_captured_file_behaviour_reports_work_with_each_hash_without_api_keys(tmp_path, kind, value):
    canonical = "f55fe457929044e4c4cdc62b4ad0a4955bd2faac2b642318649beede66086eb4"
    body = (Path(__file__).parent / "fixtures" / "vt_file_behaviours_ui_captured.json").read_text(
        encoding="utf-8")
    document = Document(f"https://www.virustotal.com/ui/files/{canonical}/behaviours?limit=40",
                        body, "json", "browser", diagnostics={
                            "request_url": f"https://www.virustotal.com/gui/file/{value}/behavior",
                            "page_url": f"https://www.virustotal.com/gui/file/{canonical}",
                        })
    transport = OfflineTransport(document)
    client = LookupClient(store=EvidenceStore(tmp_path), browser=transport, api_keys={}, interval=0)
    receipt = client.lookup_detailed(IOC(value, kind), f"virustotal.{kind}_to_command_api")
    assert receipt.status == "ok"
    assert receipt.complete
    assert receipt.outputs
    assert len(receipt.accepted) == 17
    assert all(ioc.type == "command_api" for ioc in receipt.outputs)
    assert len(transport.requests) == 1
    assert transport.requests[0].url.endswith(f"/{value}/behavior")
    assert not transport.requests[0].headers


def test_hash_browser_challenge_uses_existing_error_classification(tmp_path):
    value = HASHES["sha256"]
    document = Document(f"https://www.virustotal.com/gui/file/{value}/behavior",
                        "<body>Verify you are human</body>", "html", "browser")
    client = LookupClient(store=EvidenceStore(tmp_path), browser=OfflineTransport(document), api_keys={})
    with pytest.raises(LookupError) as failure:
        client.lookup(IOC(value, "sha256"), "virustotal.sha256_to_command_api")
    assert failure.value.status == "challenge"
    receipt = client.store.get_record(failure.value.lookup_id)
    assert receipt["status"] == "challenge"
    assert receipt["responses"]


def test_first_four_saved_workflow_replays_without_real_keys_and_keeps_admission_separate(tmp_path):
    documents = [{
        "source": "virustotal",
        "request_url": f"https://www.virustotal.com/gui/file/{value}/behavior",
        "response_url": f"https://www.virustotal.com/ui/files/{HASHES['sha256']}/behaviours",
        "operation": "file_behavior", "format": "json",
        "diagnostics": {
            "request_url": f"https://www.virustotal.com/gui/file/{value}/behavior",
            "page_url": f"https://www.virustotal.com/gui/file/{HASHES['sha256']}",
        },
        "body": json.dumps({"data": [{
            "id": HASHES['sha256'] + "_synthetic", "type": "file_behaviour",
            "attributes": {"command_executions": [f"command-for-{kind}"]},
        }]}),
    } for kind, value in HASHES.items()]
    url_doc = url_document({"Content-Disposition": "attachment; filename=payload.exe"})
    documents.append({
        "source": "virustotal",
        "request_url": f"https://www.virustotal.com/gui/url/{URL_ID}/details",
        "operation": "url_details", "format": "json",
        "response_url": url_doc.url, "body": url_doc.body,
    })
    manifest = tmp_path / "replay.json"
    manifest.write_text(json.dumps({"version": 1, "documents": documents}), encoding="utf-8")
    runner = build_runner(tmp_path / "store", replay_path=manifest)
    report = URL + "\n" + "\n".join(HASHES.values())
    with patch("socket.socket.connect", side_effect=AssertionError("Offline replay attempted network")):
        run = runner.create_run(report)
        original_graph = runner.get_result(run["id"])["graph"]
        assert runner.client.api_keys == {}
        for kind, value in list(HASHES.items()) + [("url", URL)]:
            snapshot = runner.get_result(run["id"])
            node = next(node for node in snapshot["graph"]["nodes"]
                        if node["type"] == kind and node["value"] == value)
            method_id = URL_METHOD if kind == "url" else f"virustotal.{kind}_to_command_api"
            choice = next(row for row in runner.list_methods(run["id"], node["id"])
                          if row["id"] == method_id)
            assert choice["selectable"]
            assert not choice["availability"]["api_key_configured"]
            step = runner.execute_step(run["id"], node["id"], method_id)
            assert step["outcome_status"] == "ok"
            assert step["lookup"]["outputs"]
            assert step["lookup"]["accepted"]
            assert not step["admission"]["accepted"]
            assert step["admission"]["reason"] == "no_known_unused_overlap"
            assert step["delta"]["new_edges"] == 0
        assert len(runner.client.http.requests) == 4
        reopened = build_runner(runner.client.store.directory, run_id=run["id"])
        reopened.resume(run["id"])
        result = reopened.get_result(run["id"])
        assert len(result["steps"]) == 4
        assert len(result["graph"]["nodes"]) == len(original_graph["nodes"])
        assert not result["graph"]["edges"]
        exported = reopened.export_result(run["id"], tmp_path / "investigation.json")
        assert len(exported["evidence"]["lookups"]) == 4
