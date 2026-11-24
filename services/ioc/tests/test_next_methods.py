"""Next-batch integration using captured source data and fixture-only replay."""
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
from ioc_hunter.workflow.runner import build_runner


FIXTURES = Path(__file__).parent / "fixtures"
DOMAIN = "python.org"
URL = "http://github.com/"
EMAIL_METHOD = "alienvault.domain_to_email"
URL_METHOD = "alienvault.url_to_url"


def captured_document(method):
    filename = "otx_whois_python_captured.json" if method == EMAIL_METHOD else "otx_http_github_captured.json"
    response = ("https://otx.alienvault.com/otxapi/indicators/domain/whois/python.org"
                if method == EMAIL_METHOD else
                "https://otx.alienvault.com/otxapi/indicators/url/http_scans/http%3A%2F%2Fgithub.com%2F")
    return Document(response, (FIXTURES / filename).read_text(encoding="utf-8"), "json", "browser")


class OfflineBrowser:
    offline = True

    def __init__(self, document):
        self.document = document
        self.requests = []

    def fetch(self, request):
        self.requests.append(request)
        return self.document


@pytest.mark.parametrize("method,query,output_type,count", [
    (EMAIL_METHOD, IOC(DOMAIN, "domain"), "email", 2),
    (URL_METHOD, IOC(URL, "url"), "url", 1),
])
def test_captured_next_methods_use_existing_cache_and_exact_receipts(tmp_path, method, query, output_type, count):
    browser = OfflineBrowser(captured_document(method))
    client = LookupClient(store=EvidenceStore(tmp_path), browser=browser, api_keys={}, interval=0)
    with patch("socket.socket.connect", side_effect=AssertionError("Unexpected external request")):
        first = client.lookup_detailed(query, method)
        second = client.lookup_detailed(query, method)
    assert len(first.outputs) == count
    assert all(ioc.type == output_type for ioc in first.outputs)
    assert len(first.accepted) == count
    assert not first.rejected
    assert first.status == "ok" and first.complete
    assert not first.cache_hit and second.cache_hit
    assert first.outputs == second.outputs
    assert len(browser.requests) == 1
    assert not browser.requests[0].headers
    assert LookupRecord.from_dict(client.store.get_record(first.id)).to_dict() == first.to_dict()


def test_whois_contacts_are_extracted_without_a_mailbox_host_ownership_filter(tmp_path):
    browser = OfflineBrowser(captured_document(EMAIL_METHOD))
    client = LookupClient(store=EvidenceStore(tmp_path), browser=browser, api_keys={})
    record = client.lookup_detailed(IOC(DOMAIN, "domain"), EMAIL_METHOD)
    assert all(ioc.value.endswith("@contact.gandi.net") for ioc in record.outputs)
    assert record.outputs and record.accepted
    assert all(evidence.fact_type == "whois_email" for evidence in record.evidence)


def test_whois_method_correctness_still_checks_the_input_output_and_source_field():
    query, method = IOC(DOMAIN, "domain"), get_method(EMAIL_METHOD)
    observation = parse_document(query, method, captured_document(EMAIL_METHOD)).observations[0]
    assert validate_edge(query, observation.ioc, method, observation.evidence).accepted
    for facts in ({**observation.evidence.facts, "domain": "github.com"},
                  {**observation.evidence.facts, "email": "other@python.org"},
                  {**observation.evidence.facts, "field": "name_servers"}):
        assert not validate_edge(query, observation.ioc, method,
                                 replace(observation.evidence, facts=facts)).accepted


@pytest.mark.parametrize("method,query", [(EMAIL_METHOD, IOC(DOMAIN, "domain")),
                                           (URL_METHOD, IOC(URL, "url"))])
def test_source_errors_keep_the_existing_lookup_receipt(tmp_path, method, query):
    document = replace(captured_document(method), body='{"data":"wrong","count":1}')
    client = LookupClient(store=EvidenceStore(tmp_path), browser=OfflineBrowser(document), api_keys={})
    with pytest.raises(LookupError) as failure:
        client.lookup(query, method)
    assert failure.value.status == "parse_error"
    receipt = client.store.get_record(failure.value.lookup_id)
    assert receipt["status"] == "parse_error" and receipt["responses"]
    assert not receipt["outputs"]


@pytest.mark.parametrize("method,query", [(EMAIL_METHOD, IOC(DOMAIN, "domain")),
                                           (URL_METHOD, IOC(URL, "url"))])
def test_next_methods_reuse_existing_browser_challenge_classification(tmp_path, method, query):
    document = replace(captured_document(method), format="html", body="<body>Verify you are human</body>")
    client = LookupClient(store=EvidenceStore(tmp_path), browser=OfflineBrowser(document), api_keys={})
    with pytest.raises(LookupError) as failure:
        client.lookup(query, method)
    assert failure.value.status == "challenge"
    assert client.store.get_record(failure.value.lookup_id)["status"] == "challenge"


def test_stored_http_scan_does_not_validate_an_outgoing_link_kind():
    query, method = IOC(URL, "url"), get_method(URL_METHOD)
    observation = parse_document(query, method, captured_document(URL_METHOD)).observations[0]
    assert validate_edge(query, observation.ioc, method, observation.evidence).accepted
    wrong = replace(observation.evidence, facts={**observation.evidence.facts, "kind": "outgoing_link"})
    assert not validate_edge(query, observation.ioc, method, wrong).accepted


def test_multiple_stored_redirect_rows_deduplicate_outputs_and_retain_each_source_row(tmp_path):
    document = captured_document(URL_METHOD)
    row = json.loads(document.body)["data"][0]
    other = {**row, "value": "HTTP/1.1 302 Found Location: https://www.python.org/"}
    document = replace(document, body=json.dumps({"data": [row, other, row], "count": 3}))
    client = LookupClient(store=EvidenceStore(tmp_path), browser=OfflineBrowser(document), api_keys={})
    receipt = client.lookup_detailed(IOC(URL, "url"), URL_METHOD)
    assert [ioc.value for ioc in receipt.outputs] == ["https://github.com/", "https://www.python.org/"]
    assert len(receipt.accepted) == 3 and len(receipt.evidence) == 3
    assert len({evidence.locator for evidence in receipt.evidence}) == 3


def test_next_methods_saved_replay_keeps_extraction_and_admission_separate(tmp_path):
    entries = []
    for method_id, query in ((EMAIL_METHOD, IOC(DOMAIN, "domain")), (URL_METHOD, IOC(URL, "url"))):
        from ioc_hunter.providers import requests_for
        request = requests_for(query, get_method(method_id))[0][1]
        document = captured_document(method_id)
        entries.append({"source": "alienvault", "request_url": request.url,
                        "response_url": document.url, "operation": request.operation,
                        "format": document.format, "body": document.body})
    manifest = tmp_path / "replay.json"
    manifest.write_text(json.dumps({"version": 1, "documents": entries}), encoding="utf-8")
    runner = build_runner(tmp_path / "store", replay_path=manifest)
    with patch("socket.socket.connect", side_effect=AssertionError("Replay attempted network")):
        run = runner.create_run("The domain python.org was mentioned.\nThe URL http://github.com/ was mentioned.")
        for method_id, kind, value in ((EMAIL_METHOD, "domain", DOMAIN), (URL_METHOD, "url", URL)):
            result = runner.get_result(run["id"])
            node = next(node for node in result["graph"]["nodes"]
                        if node["type"] == kind and node["value"] == value)
            choice = next(row for row in runner.list_methods(run["id"], node["id"])
                          if row["id"] == method_id)
            assert choice["selectable"]
            step = runner.execute_step(run["id"], node["id"], method_id)
            assert step["outcome_status"] == "ok"
            assert step["lookup"]["outputs"] and step["lookup"]["accepted"]
            assert not step["admission"]["accepted"]
            assert step["admission"]["reason"] == "no_known_unused_overlap"
            assert not step["delta"]["new_edges"]
        reopened = build_runner(runner.client.store.directory, run_id=run["id"])
        reopened.resume(run["id"])
        exported = reopened.export_result(run["id"], tmp_path / "result.json")
        assert len(exported["evidence"]["lookups"]) == 2
