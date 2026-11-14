"""Synthetic DNS contracts for composed lookups; no live source observations.

All documents below are constructed fixtures. Their addresses use documentation
ranges and their provider URLs exercise the real adapters without networking.
"""
from html import escape
import json
from pathlib import Path
import tempfile
import unittest
from urllib.parse import quote

from ioc_hunter import IOC, LookupClient, LookupError, get_method
from ioc_hunter.providers import parse_document, requests_for
from ioc_hunter.storage import EvidenceStore
from ioc_hunter.transport import Document, allowed_url
from ioc_hunter.workflow.replay import ReplayTransport


class OfflineSequence:
    offline = True

    def __init__(self, *documents):
        self.documents = list(documents)
        self.requests = []

    def fetch(self, request):
        self.requests.append(request)
        if not self.documents:
            raise AssertionError("Unexpected fixture request; networking is disabled")
        document = self.documents.pop(0)
        if isinstance(document, Exception):
            raise document
        return document


def rapid_document(query, kind, rows):
    """Synthetic RapidDNS result table with a completed-empty marker."""
    route = "subdomain" if kind == "domain" else "sameip"
    cells = "".join("<tr>" + "".join(f"<td>{escape(value)}</td>" for value in row) + "</tr>"
                    for row in rows)
    body = (f'<div id="result"><h3>{escape(query)}</h3><p>Total: {len(rows)}</p>'
            '<table><tr><th>Domain</th><th>Address</th><th>Type</th></tr>'
            + cells + "</table>" + ("No results" if not rows else "") + "</div>")
    return Document(f"https://rapiddns.io/{route}/{quote(query, safe='')}?page=1", body, "html", "replay")


def otx_document(query, rows, *, api=False):
    """Synthetic OTX passive-DNS envelope, including an unrelated pulse."""
    kind = "IPv4" if ":" not in query and query.replace(".", "").isdigit() else "domain"
    path = (f"/api/v1/indicators/{kind}/{quote(query, safe='')}/passive_dns" if api
            else f"/otxapi/indicators/{kind}/passive_dns/{quote(query, safe='')}")
    return Document("https://otx.alienvault.com" + path, json.dumps({
        "passive_dns": [{"hostname": domain, "address": address, "record_type": record_type}
                        for domain, address, record_type in rows],
        "pulse_info": {"indicators": [{"type": "IPv4", "indicator": "203.0.113.99"}]},
    }), "json", "replay")


class DNSDiscoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = EvidenceStore(self.temp.name)

    def client(self, transport, **kwargs):
        return LookupClient(store=self.store, http=transport, browser=transport,
                            interval=0, cache_ttl=kwargs.pop("cache_ttl", 0), **kwargs)

    def test_four_rapiddns_ip_directions_share_discovery_without_returning_input(self):
        for input_type, input_value in (("ipv4", "192.0.2.10"), ("ipv6", "2001:db8::10")):
            for output_type, expected in (("ipv4", "192.0.2.20"), ("ipv6", "2001:db8::20")):
                with self.subTest(input_type=input_type, output_type=output_type):
                    seed_type = "AAAA" if input_type == "ipv6" else "A"
                    seed = rapid_document(input_value, input_type, [
                        ("python.org", input_value, seed_type),
                        ("python.org", input_value, seed_type),
                        ("github.com", "203.0.113.7", "A"),
                    ])
                    expanded = rapid_document("python.org", "domain", [
                        ("python.org", input_value, seed_type),
                        ("python.org", "192.0.2.20", "A"),
                        ("docs.python.org", "2001:db8::20", "AAAA"),
                    ])
                    transport = OfflineSequence(seed, expanded)
                    client = self.client(transport)
                    query = IOC(input_value, input_type, ["source report"], "cti report")
                    method_id = f"rapiddns.{input_type}_to_{output_type}"
                    outputs = client.lookup(query, method_id)
                    self.assertEqual([(item.type, item.value) for item in outputs], [(output_type, expected)])
                    self.assertEqual(len(transport.requests), 2)
                    self.assertIn("/subdomain/python.org", transport.requests[1].url)
                    receipt = client.latest_record(query, method_id)
                    self.assertEqual(receipt["status"], "ok")
                    self.assertTrue(receipt["complete"])
                    self.assertEqual(len(receipt["responses"]), 2)
                    self.assertTrue(all(ev["query_value"] == input_value for ev in receipt["evidence"]))
                    self.assertTrue(all(ev["response_sha256"] for ev in receipt["evidence"]))
                    self.assertFalse(receipt["cache_hit"])
                    self.assertNotIn("known_iocs", receipt)
                    self.assertNotIn("graph", receipt)
                    self.assertEqual(query.context, ["source report"])

    def test_otx_ip_to_ip_uses_only_passive_dns_and_excludes_echo(self):
        query = IOC("192.0.2.10", "ipv4")
        transport = OfflineSequence(
            otx_document(query.value, [("python.org", query.value, "A")]),
            otx_document("python.org", [("python.org", query.value, "A"),
                                        ("docs.python.org", "192.0.2.20", "A")]),
        )
        client = self.client(transport)
        outputs = client.lookup(query, "alienvault.ipv4_to_ipv4")
        self.assertEqual([item.value for item in outputs], ["192.0.2.20"])
        self.assertEqual(len(transport.requests), 2)
        receipt = client.latest_record(query, "alienvault.ipv4_to_ipv4")
        self.assertEqual(receipt["status"], "ok")
        self.assertNotIn("203.0.113.99", [item.value for item in outputs])
        self.assertEqual(receipt["evidence"][0]["facts"]["domain"], "docs.python.org")

    def test_url_hostname_prepares_query_but_outputs_come_from_source_rows(self):
        query = IOC("https://python.org/downloads/?release=3", "url")
        transport = OfflineSequence(rapid_document("python.org", "domain", [
            ("docs.python.org", "2001:db8::20", "AAAA"),
            ("www.python.org", "192.0.2.20", "A"),
        ]))
        client = self.client(transport)
        outputs = client.lookup(query, "rapiddns.url_to_domain")
        self.assertEqual({item.value for item in outputs}, {"docs.python.org", "www.python.org"})
        self.assertNotIn("python.org", [item.value for item in outputs])
        self.assertEqual(len(transport.requests), 1)
        self.assertTrue(all(allowed_url("rapiddns", request.url) for request in transport.requests))
        receipt = client.latest_record(query, "rapiddns.url_to_domain")
        self.assertTrue(all(ev["query_value"] == query.value for ev in receipt["evidence"]))

    def test_url_hostname_is_not_returned_when_provider_returns_no_rows(self):
        transport = OfflineSequence(rapid_document("python.org", "domain", []))
        client = self.client(transport)
        query = IOC("https://python.org/downloads/", "url")
        self.assertEqual(client.lookup(query, "rapiddns.url_to_domain"), [])
        self.assertEqual(client.latest_record(query, "rapiddns.url_to_domain")["status"], "empty")

    def test_url_with_ip_hostname_fails_before_acquisition(self):
        transport = OfflineSequence()
        client = self.client(transport)
        with self.assertRaises(LookupError) as raised:
            client.lookup(IOC("https://192.0.2.10/download", "url"), "rapiddns.url_to_domain")
        self.assertEqual(raised.exception.status, "invalid_request")
        self.assertEqual(transport.requests, [])

    def test_response_for_another_stage_query_is_rejected(self):
        query = IOC("192.0.2.10", "ipv4")
        method = get_method("rapiddns.ipv4_to_ipv4")
        _, request = requests_for(query, method)[0]
        document = rapid_document("192.0.2.11", "ipv4", [("python.org", query.value, "A")])
        document.diagnostics["request_context"] = request.context
        with self.assertRaises(LookupError) as raised:
            parse_document(query, method, document)
        self.assertEqual(raised.exception.status, "invalid_response")

    def test_seed_rows_for_other_addresses_do_not_schedule_domain_reads(self):
        query = IOC("192.0.2.10", "ipv4")
        transport = OfflineSequence(rapid_document(query.value, query.type, [
            ("github.com", "192.0.2.11", "A"),
        ]))
        client = self.client(transport)
        self.assertEqual(client.lookup(query, "rapiddns.ipv4_to_ipv4"), [])
        self.assertEqual(len(transport.requests), 1)

    def test_typed_otx_followup_retains_configured_api_fallback(self):
        query = IOC("192.0.2.10", "ipv4")
        challenge = Document("https://otx.alienvault.com/indicator/domain/python.org",
                             "<h1>captcha</h1>", "html", "replay")
        transport = OfflineSequence(
            otx_document(query.value, [("python.org", query.value, "A")]),
            challenge,
            otx_document("python.org", [("python.org", "192.0.2.20", "A")], api=True),
        )
        client = self.client(transport, api_keys={"alienvault": "synthetic-otx-key"})
        self.assertEqual([item.value for item in client.lookup(query, "alienvault.ipv4_to_ipv4")],
                         ["192.0.2.20"])
        self.assertEqual(len(transport.requests), 3)
        self.assertEqual(transport.requests[-1].headers["X-OTX-API-KEY"], "synthetic-otx-key")
        self.assertEqual(transport.requests[-1].context["stage"], "expand")
        receipt = client.latest_record(query, "alienvault.ipv4_to_ipv4")
        self.assertEqual(receipt["transport_errors"][0]["status"], "challenge")
        self.assertNotIn("synthetic-otx-key", json.dumps(receipt))

    def test_followup_limit_returns_partial_source_results(self):
        query = IOC("192.0.2.10", "ipv4")
        transport = OfflineSequence(
            rapid_document(query.value, query.type, [("python.org", query.value, "A"),
                                                      ("github.com", query.value, "A")]),
            rapid_document("python.org", "domain", [("python.org", "192.0.2.20", "A")]),
        )
        client = self.client(transport, max_followups=1)
        self.assertEqual([item.value for item in client.lookup(query, "rapiddns.ipv4_to_ipv4")],
                         ["192.0.2.20"])
        receipt = client.latest_record(query, "rapiddns.ipv4_to_ipv4")
        self.assertEqual(receipt["status"], "partial")
        self.assertIn("followup_limit", receipt["partial_reasons"])
        self.assertEqual(len(transport.requests), 2)

    def test_offline_manifest_replays_required_reads_with_normal_receipts(self):
        query = IOC("192.0.2.10", "ipv4")
        documents = [rapid_document(query.value, query.type, [("python.org", query.value, "A")]),
                     rapid_document("python.org", "domain", [("python.org", "192.0.2.20", "A")])]
        manifest = Path(self.temp.name) / "synthetic-dns-manifest.json"
        manifest.write_text(json.dumps({"version": 1, "documents": [
            {"source": "rapiddns", "request_url": item.url, "operation": "dns",
             "response_url": item.url, "body": item.body, "format": item.format}
            for item in documents
        ]}), encoding="utf-8")
        replay = ReplayTransport(manifest)
        client = self.client(replay)
        self.assertEqual([item.value for item in client.lookup(query, "rapiddns.ipv4_to_ipv4")],
                         ["192.0.2.20"])
        self.assertEqual(len(replay.requests), 2)
        receipt = client.latest_record(query, "rapiddns.ipv4_to_ipv4")
        self.assertEqual(receipt["status"], "ok")
        snapshots = [self.store.get_snapshot(item["snapshot_id"]) for item in receipt["responses"]]
        self.assertEqual([item["transport"] for item in snapshots], ["replay", "replay"])
        self.assertEqual([item["diagnostics"]["request_context"]["stage"] for item in snapshots],
                         ["seed", "expand"])


if __name__ == "__main__":
    unittest.main()
