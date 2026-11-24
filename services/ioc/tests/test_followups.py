"""Synthetic provider-stage scenarios for the shared acquisition executor.

Provider dispatch is patched, while caching, receipts, output validation, limits
and transport selection use the real LookupClient. No networking is available.
"""
import json
import tempfile
import unittest
from unittest.mock import patch

from ioc_hunter import IOC, LookupClient, LookupError, get_method
from ioc_hunter.providers.base import FollowUp
from ioc_hunter.providers.common import ObservationBuilder
from ioc_hunter.storage import EvidenceStore
from ioc_hunter.transport import Document, FetchRequest


SOURCE = "rapiddns"
ROOT_URL = "https://rapiddns.io/subdomain/python.org?page=1"


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


def document(url, address=""):
    return Document(url, json.dumps({"address": address}), "json", "replay")


def child(key, *, url=None, context=None, source=SOURCE):
    request = FetchRequest(source, url or f"https://rapiddns.io/subdomain/python.org?stage={key}",
                           "dns", context=context or {})
    return FollowUp(key, (("http", request),))


def observed_page(query, method, response, *, children=(), next_url=""):
    """Build actual DNS evidence so acceptance still crosses the real validator."""
    builder = ObservationBuilder(query, method, response)
    address = json.loads(response.body).get("address", "")
    if address:
        builder.emit("ipv4", address, "$.address", {"address": address}, "dns_record",
                     {"domain": "python.org", "ip": address, "record_type": "A"})
    builder.result.followups.extend(children)
    builder.result.next_url = next_url
    return builder.result


class FollowUpExecutorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = EvidenceStore(self.temp.name)
        self.query = IOC("python.org", "domain")
        self.method = get_method("rapiddns.domain_to_ipv4")

    def client(self, transport, **kwargs):
        return LookupClient(store=self.store, http=transport, browser=transport, interval=0,
                            cache_ttl=kwargs.pop("cache_ttl", 0), **kwargs)

    def root_routes(self, *_args):
        return [("http", FetchRequest(SOURCE, ROOT_URL, "dns", context={"stage": "seed"}))]

    def test_children_are_deduplicated_across_discovery_pages(self):
        a, b = child("a"), child("b")
        page_two = ROOT_URL.replace("page=1", "page=2")
        transport = OfflineSequence(document(ROOT_URL), document(page_two),
                                    document(a.routes[0][1].url, "192.0.2.20"),
                                    document(b.routes[0][1].url, "192.0.2.21"))

        def parse(query, method, response):
            if response.url == ROOT_URL:
                return observed_page(query, method, response, children=(a,), next_url=page_two)
            if response.url == page_two:
                return observed_page(query, method, response, children=(a, b))
            return observed_page(query, method, response)

        client = self.client(transport)
        with patch("ioc_hunter.lookup.requests_for", side_effect=self.root_routes), \
                patch("ioc_hunter.lookup.parse_document", side_effect=parse):
            outputs = client.lookup(self.query, self.method.id)
        self.assertEqual({item.value for item in outputs}, {"192.0.2.20", "192.0.2.21"})
        self.assertEqual(len(transport.requests), 4)
        self.assertEqual(sum(request.url == a.routes[0][1].url for request in transport.requests), 1)
        self.assertTrue(client.latest_record(self.query, self.method.id)["complete"])

    def test_page_limit_applies_to_each_stage_and_preserves_required_reads(self):
        a = child("a")
        root_next = ROOT_URL.replace("page=1", "page=2")
        child_next = a.routes[0][1].url + "&page=2"
        transport = OfflineSequence(document(ROOT_URL), document(a.routes[0][1].url, "192.0.2.20"))

        def parse(query, method, response):
            return (observed_page(query, method, response, children=(a,), next_url=root_next)
                    if response.url == ROOT_URL
                    else observed_page(query, method, response, next_url=child_next))

        client = self.client(transport, max_pages=1)
        with patch("ioc_hunter.lookup.requests_for", side_effect=self.root_routes), \
                patch("ioc_hunter.lookup.parse_document", side_effect=parse):
            outputs = client.lookup(self.query, self.method.id)
        self.assertEqual([item.value for item in outputs], ["192.0.2.20"])
        self.assertEqual(len(transport.requests), 2)
        receipt = client.latest_record(self.query, self.method.id)
        self.assertEqual(receipt["status"], "partial")
        self.assertIn("page_limit", receipt["partial_reasons"])

    def test_later_page_terminal_failure_stops_siblings_and_retains_outputs(self):
        for status in ("rate_limited", "budget_exhausted", "unsafe_redirect", "unsafe_pagination",
                       "login_required", "access_denied"):
            with self.subTest(status=status):
                a, b = child("a"), child("b")
                next_url = a.routes[0][1].url + "&page=2"
                transport = OfflineSequence(document(ROOT_URL),
                                            document(a.routes[0][1].url, "192.0.2.20"),
                                            LookupError(status, "Synthetic terminal failure", retry_after=1))

                def parse(query, method, response):
                    return (observed_page(query, method, response, children=(a, b))
                            if response.url == ROOT_URL
                            else observed_page(query, method, response, next_url=next_url))

                client = self.client(transport, max_pages=2)
                with patch("ioc_hunter.lookup.requests_for", side_effect=self.root_routes), \
                        patch("ioc_hunter.lookup.parse_document", side_effect=parse):
                    outputs = client.lookup(self.query, self.method.id)
                self.assertEqual([item.value for item in outputs], ["192.0.2.20"])
                self.assertEqual(len(transport.requests), 3)
                self.assertFalse(any(request.url == b.routes[0][1].url for request in transport.requests))
                receipt = client.latest_record(self.query, self.method.id)
                self.assertEqual(receipt["status"], "partial")
                self.assertIn("later_page_failed:" + status, receipt["partial_reasons"])
                self.assertEqual(receipt["outcome_reason"], "acquisition_stopped:" + status)

    def test_first_page_terminal_failure_preserves_parent_outputs_and_stops_queue(self):
        a, b = child("a"), child("b")
        transport = OfflineSequence(document(ROOT_URL, "192.0.2.20"),
                                    LookupError("access_denied", "Synthetic account restriction"))

        def parse(query, method, response):
            return observed_page(query, method, response, children=(a, b))

        client = self.client(transport)
        with patch("ioc_hunter.lookup.requests_for", side_effect=self.root_routes), \
                patch("ioc_hunter.lookup.parse_document", side_effect=parse):
            outputs = client.lookup(self.query, self.method.id)
        self.assertEqual([item.value for item in outputs], ["192.0.2.20"])
        self.assertEqual(len(transport.requests), 2)
        receipt = client.latest_record(self.query, self.method.id)
        self.assertEqual(receipt["status"], "partial")
        self.assertIn("followup_failed:access_denied", receipt["partial_reasons"])

    def test_context_isolates_shared_report_url_cache_and_survives_reuse(self):
        shared = "https://rapiddns.io/subdomain/python.org?report=1"
        a = child("a", url=shared, context={"stage": "a"})
        b = child("b", url=shared, context={"stage": "b"})
        transport = OfflineSequence(document(ROOT_URL), document(shared, "192.0.2.20"),
                                    document(shared, "192.0.2.21"))
        contexts = []

        def parse(query, method, response):
            contexts.append(response.diagnostics["request_context"]["stage"])
            return (observed_page(query, method, response, children=(a, b))
                    if response.url == ROOT_URL else observed_page(query, method, response))

        client = self.client(transport, cache_ttl=86400)
        with patch("ioc_hunter.lookup.requests_for", side_effect=self.root_routes), \
                patch("ioc_hunter.lookup.parse_document", side_effect=parse):
            first = client.lookup(self.query, self.method.id)
            first_receipt = client.latest_record(self.query, self.method.id)
            second = client.lookup(self.query, self.method.id)
        self.assertEqual({item.value for item in first}, {"192.0.2.20", "192.0.2.21"})
        self.assertEqual({item.value for item in second}, {"192.0.2.20", "192.0.2.21"})
        self.assertEqual(len(transport.requests), 3)
        self.assertEqual(contexts, ["seed", "a", "b", "seed", "a", "b"])
        self.assertFalse(first_receipt["cache_hit"])
        self.assertTrue(client.latest_record(self.query, self.method.id)["cache_hit"])

    def test_zero_followup_budget_preserves_direct_outputs_with_partial_receipt(self):
        transport = OfflineSequence(document(ROOT_URL, "192.0.2.20"))

        def parse(query, method, response):
            return observed_page(query, method, response, children=(child("a"),))

        client = self.client(transport, max_followups=0)
        with patch("ioc_hunter.lookup.requests_for", side_effect=self.root_routes), \
                patch("ioc_hunter.lookup.parse_document", side_effect=parse):
            outputs = client.lookup(self.query, self.method.id)
        self.assertEqual([item.value for item in outputs], ["192.0.2.20"])
        self.assertEqual(len(transport.requests), 1)
        receipt = client.latest_record(self.query, self.method.id)
        self.assertEqual(receipt["status"], "partial")
        self.assertIn("followup_limit", receipt["partial_reasons"])

    def test_cross_provider_child_never_reaches_transport(self):
        foreign = child("foreign", url="https://www.virustotal.com/gui/domain/python.org/details",
                        source="virustotal")
        transport = OfflineSequence(document(ROOT_URL, "192.0.2.20"))

        def parse(query, method, response):
            return observed_page(query, method, response, children=(foreign,))

        client = self.client(transport)
        with patch("ioc_hunter.lookup.requests_for", side_effect=self.root_routes), \
                patch("ioc_hunter.lookup.parse_document", side_effect=parse):
            outputs = client.lookup(self.query, self.method.id)
        self.assertEqual([item.value for item in outputs], ["192.0.2.20"])
        self.assertEqual(len(transport.requests), 1)
        receipt = client.latest_record(self.query, self.method.id)
        self.assertEqual(receipt["status"], "partial")
        self.assertIn("followup_failed:invalid_request", receipt["partial_reasons"])


if __name__ == "__main__":
    unittest.main()
