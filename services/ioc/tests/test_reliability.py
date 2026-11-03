"""Regressions for observed website integration failures; no live network."""
from dataclasses import replace
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from ioc_hunter import IOC, LookupClient, LookupError, get_method
from ioc_hunter.providers import parse_document, requests_for
from ioc_hunter.storage import EvidenceStore
from ioc_hunter.transport import BrowserTransport, Document, FetchRequest
from ioc_hunter.transport.browser import response_matches
import test_browser_transport
from test_lookup import FakeTransport, fixture


class ContractTests(unittest.TestCase):
    def test_current_captured_website_schemas(self):
        with tempfile.TemporaryDirectory() as directory:
            transport = FakeTransport(fixture("otx_ui_dns_captured.json", "alienvault"),
                                      fixture("vt_ipv6_ui_captured.json", "virustotal"))
            client = LookupClient(store=EvidenceStore(directory), browser=transport, interval=0)
            ips = client.lookup(IOC("example.com", "domain"), "alienvault.domain_to_ipv4")
            self.assertEqual([ip.value for ip in ips], ["172.66.147.243"])
            domains = client.lookup(IOC("2606:4700:4700::1111", "ipv6"), "virustotal.ipv6_to_domain")
            self.assertEqual({d.value for d in domains}, {"one.one.one.one", "1dot1dot1dot1.cloudflare-dns.com"})

    def test_paper_page_primary_public_api_optional(self):
        ioc = IOC("example.com", "domain")
        routes = requests_for(ioc, get_method("alienvault.domain_to_url"), "secret")
        self.assertEqual(routes[0][1].url, "https://otx.alienvault.com/indicator/domain/example.com")
        self.assertEqual(routes[0][1].response_paths, ("/otxapi/indicators/domain/url_list/example.com",))
        self.assertEqual(routes[1][0], "http")
        self.assertIn("/api/v1/indicators/", routes[1][1].url)
        url_route = requests_for(IOC("http://example.com/", "url"), get_method("alienvault.url_to_domain"))[0][1]
        self.assertEqual(url_route.url, "https://otx.alienvault.com/indicator/url/http:%2F%2Fexample.com%2F")
        self.assertTrue(response_matches(url_route, "https://otx.alienvault.com/otxapi/indicators/url/general/http%3A%252F%252Fexample.com%252F"))
        self.assertFalse(response_matches(url_route, "https://otx.alienvault.com/otxapi/indicators/url/general/http%3A%252F%252Fother.example%252F"))

    def test_ipv6_match_is_typed_and_operation_bound(self):
        request = requests_for(IOC("2606:4700:4700::1111", "ipv6"), get_method("virustotal.ipv6_to_domain"))[0][1]
        base = "https://www.virustotal.com/ui/ip_addresses/"
        self.assertTrue(response_matches(request, base + "2606:4700:4700::1111/resolutions"))
        self.assertTrue(response_matches(request, base + "2606:4700:4700:0:0:0:0:1111/resolutions"))
        for suffix in ["2606:4700:4700::1001/resolutions", "2606:4700:4700::1111/urls", "2606:4700:4700::1111/resolutions?cursor=next"]:
            self.assertFalse(response_matches(request, base + suffix))
        self.assertFalse(response_matches(request, "https://evil.example/ui/ip_addresses/2606:4700:4700::1111/resolutions"))

    def test_otx_loading_outside_table_and_unrelated_whois(self):
        html = '<table><tr><th>Record</th></tr><tr><td>WHOIS</td></tr></table><div id="url_list"><div class="loading"></div><table><tr><th>URL</th></tr></table>No Entries Found</div>'
        with self.assertRaises(LookupError) as ctx:
            parse_document(IOC("example.com", "domain"), get_method("alienvault.domain_to_url"), Document("https://otx.alienvault.com/indicator/domain/example.com", html, "html"))
        self.assertEqual(ctx.exception.status, "loading_page")

    def test_otx_query_type_header_and_scoping(self):
        table = '<table><tr><th>Hostname</th><th>Query Type</th><th>Address</th></tr><tr><td>example.com</td><td>A</td><td>192.0.2.1</td></tr></table>'
        doc = Document("https://otx.alienvault.com/indicator/domain/example.com", table.replace("192.0.2.1", "192.0.2.9") + '<div id="passive_dns">' + table + '</div>', "html")
        result = parse_document(IOC("example.com", "domain"), get_method("alienvault.domain_to_ipv4"), doc)
        self.assertEqual([o.ioc.value for o in result.observations], ["192.0.2.1"])
        self.assertFalse(result.complete)

    def test_missing_country_is_distinct_from_broken_schema(self):
        ioc = IOC("1.1.1.1", "ipv4")
        method = get_method("virustotal.ipv4_to_geo_location")
        doc = Document("https://www.virustotal.com/ui/ip_addresses/1.1.1.1", '{"data":{"id":"1.1.1.1","attributes":{"asn":13335}}}', "json")
        result = parse_document(ioc, method, doc)
        self.assertEqual(result.reason, "country_unavailable")
        self.assertEqual(result.observations, [])
        for body in ['{}', '{"data":[]}', '{"data":{"id":"1.1.1.1"}}']:
            with self.assertRaises(LookupError):
                parse_document(ioc, method, replace(doc, body=body))

    def test_final_url_alone_is_not_a_direct_redirect(self):
        doc = fixture("vt_url.json", "virustotal")
        data = json.loads(doc.body)
        del data["data"]["attributes"]["redirection_chain"]
        data["data"]["attributes"]["outgoing_links"] = []
        result = parse_document(IOC("https://example.com/a", "url"), get_method("virustotal.url_to_url"), replace(doc, body=json.dumps(data)))
        self.assertEqual(result.observations, [])

    def test_cache_version_and_access_isolation(self):
        req = FetchRequest("virustotal", "https://www.virustotal.com/gui/domain/example.com/relations", "dns")
        self.assertNotEqual(EvidenceStore.cache_key(req, "browser"), EvidenceStore.cache_key(replace(req, integration_version="3"), "browser"))
        self.assertNotEqual(EvidenceStore.cache_key(req, "browser"), EvidenceStore.cache_key(req, "browser", "account-fingerprint"))

    def test_timeout_retry_retains_failed_snapshot_then_succeeds(self):
        with tempfile.TemporaryDirectory() as directory:
            doc = Document("https://otx.alienvault.com/indicator/domain/example.com", "Loading...", "html", diagnostics={"terminal_state":"timeout"})
            transport = FakeTransport(doc, fixture("otx_dns.json", "alienvault"))
            client = LookupClient(store=EvidenceStore(directory), browser=transport, interval=0)
            query = IOC("example.com", "domain")
            with patch("ioc_hunter.lookup.time.sleep"):
                self.assertEqual(len(client.lookup(query, "alienvault.domain_to_ipv4")), 1)
            record = client.latest_record(query, "alienvault.domain_to_ipv4")
            self.assertEqual(len(record["responses"]), 2)
            self.assertEqual(len(transport.requests), 2)
            self.assertTrue(record["transport_errors"][0]["retried"])

    def test_browser_pagination_is_truthfully_partial(self):
        with tempfile.TemporaryDirectory() as directory:
            doc = fixture("vt_dns.json", "virustotal")
            data = json.loads(doc.body)
            data["links"] = {"next": doc.url + "?cursor=next"}
            transport = FakeTransport(replace(doc, body=json.dumps(data), transport="browser"))
            client = LookupClient(store=EvidenceStore(directory), browser=transport, interval=0)
            query = IOC("example.com", "domain")
            client.lookup(query, "virustotal.domain_to_ipv4")
            record = client.latest_record(query, "virustotal.domain_to_ipv4")
            self.assertEqual(record["status"], "partial")
            self.assertIn("browser_pagination_not_verified", record["partial_reasons"])
            self.assertEqual(len(transport.requests), 1)

    def test_all_rejected_receipt_does_not_claim_provider_empty(self):
        with tempfile.TemporaryDirectory() as directory:
            doc = fixture("otx_dns.json", "alienvault")
            doc.body = '{"passive_dns":[{"hostname":"sub.example.com","address":"192.0.2.1","record_type":"A"}]}'
            client = LookupClient(store=EvidenceStore(directory), browser=FakeTransport(doc), interval=0)
            query = IOC("example.com", "domain")
            self.assertEqual(client.lookup(query, "alienvault.domain_to_ipv4"), [])
            self.assertEqual(client.latest_record(query, "alienvault.domain_to_ipv4")["outcome_reason"], "all_candidates_rejected")


@unittest.skipUnless(importlib.util.find_spec("playwright"), "Optional browser dependency not installed")
class BrowserReliabilityTests(unittest.TestCase):
    factory = test_browser_transport.BrowserTests.factory

    def test_ui_pagination_reuses_session_and_clicks_next(self):
        path = "/otxapi/indicators/domain/url_list/example.com"
        navigations = []
        requests = []
        html = '<div id="url_list"><button class="page-change increment" onclick="fetch(\'' + path + '?page=2&limit=10\')">Next</button></div><script>fetch("' + path + '")</script>'
        def handle(route):
            url = route.request.url
            if path in url:
                requests.append(url)
                second = "page=2" in url
                data = {"url_list":[{"url":"https://example.com/" + ("second" if second else "first")}],"has_next":not second}
                route.fulfill(status=200,content_type="application/json",body=json.dumps(data))
            else:
                navigations.append(url)
                route.fulfill(status=200,content_type="text/html",body=html)
        with tempfile.TemporaryDirectory() as directory, patch("playwright.sync_api.sync_playwright", self.factory(handle)):
            client = LookupClient(store=EvidenceStore(directory),browser=BrowserTransport(timeout=3),interval=0,max_pages=2)
            query = IOC("example.com","domain")
            outputs = client.lookup(query,"alienvault.domain_to_url")
            self.assertEqual({o.value for o in outputs},{"https://example.com/first","https://example.com/second"})
            record = client.latest_record(query,"alienvault.domain_to_url")
            self.assertTrue(record["complete"])
            self.assertEqual(len(record["responses"]),2)
            # Raw cached pages cannot replace the live GUI state needed by Next.
            again = client.lookup(query,"alienvault.domain_to_url")
            self.assertEqual(len(again),2)
            self.assertFalse(client.latest_record(query,"alienvault.domain_to_url")["cache_hit"])
        self.assertEqual(len(navigations),2)
        self.assertEqual(len(requests),4)

    def test_continuation_requires_original_session(self):
        req = requests_for(IOC("example.com","domain"),get_method("alienvault.domain_to_url"))[0][1]
        with self.assertRaises(LookupError) as ctx:
            BrowserTransport().fetch(replace(req,continuation_url="https://otx.alienvault.com/otxapi/indicators/domain/url_list/example.com?page=2"))
        self.assertEqual(ctx.exception.status,"pagination_unavailable")

    def test_unrelated_table_does_not_end_wait(self):
        path = "/otxapi/indicators/domain/url_list/example.com"
        html = '<table><tbody><tr><td>WHOIS</td></tr></tbody></table><script>setTimeout(()=>fetch("' + path + '"),500)</script>'
        def handle(route):
            route.fulfill(status=200, content_type="application/json" if route.request.url.endswith(path) else "text/html",
                          body='{"url_list":[]}' if route.request.url.endswith(path) else html)
        req = FetchRequest("alienvault", "https://otx.alienvault.com/indicator/domain/example.com", "urls", (path,))
        with patch("playwright.sync_api.sync_playwright", self.factory(handle)):
            doc = BrowserTransport(timeout=3).fetch(req)
        self.assertEqual(doc.format, "json")
        self.assertEqual(doc.diagnostics["terminal_state"], "response_complete")

    def test_bootstrap_429_preserves_retry_after_and_snapshot(self):
        def handle(route):
            bootstrap = route.request.url.endswith("/otxapi/env")
            route.fulfill(status=429 if bootstrap else 200,
                          headers={"Retry-After":"123"} if bootstrap else {},
                          content_type="application/json" if bootstrap else "text/html",
                          body='{}' if bootstrap else '<script>fetch("/otxapi/env")</script>')
        req = FetchRequest("alienvault", "https://otx.alienvault.com/indicator/domain/example.com", "dns", bootstrap_paths=("/otxapi/env",))
        with patch("playwright.sync_api.sync_playwright", self.factory(handle)), self.assertRaises(LookupError) as ctx:
            BrowserTransport(timeout=3).fetch(req)
        self.assertEqual(ctx.exception.status, "rate_limited")
        self.assertEqual(ctx.exception.retry_after, 123)
        self.assertIsNotNone(ctx.exception.document)

    def test_anonymous_me_401_does_not_block_dns(self):
        path = "/ui/ip_addresses/2606:4700:4700::1111/resolutions"
        def handle(route):
            is_me = route.request.url.endswith("/ui/me")
            is_dns = route.request.url.endswith(path)
            route.fulfill(status=401 if is_me else 200, content_type="application/json" if is_me or is_dns else "text/html",
                          body='{"data":[]}' if is_dns else '{}' if is_me else '<script>fetch("/ui/me");fetch("' + path + '");</script>')
        req = requests_for(IOC("2606:4700:4700::1111", "ipv6"), get_method("virustotal.ipv6_to_domain"))[0][1]
        with patch("playwright.sync_api.sync_playwright", self.factory(handle)):
            doc = BrowserTransport(timeout=3).fetch(req)
        self.assertEqual(doc.format, "json")

    def test_timeout_never_accepts_unrelated_table(self):
        def handle(route):
            route.fulfill(status=200, content_type="text/html", body='<table><tr><td>Unrelated result</td></tr></table>')
        req = FetchRequest("virustotal", "https://www.virustotal.com/gui/domain/example.com/relations", "dns", ("/ui/domains/example.com/resolutions",))
        with patch("playwright.sync_api.sync_playwright", self.factory(handle)):
            doc = BrowserTransport(timeout=0.5).fetch(req)
        self.assertEqual(doc.diagnostics["terminal_state"], "timeout")
        with self.assertRaises(LookupError):
            parse_document(IOC("example.com", "domain"), get_method("virustotal.domain_to_ipv4"), doc)

    def test_provider_not_found_is_not_a_loading_timeout(self):
        def handle(route):
            route.fulfill(status=200, content_type="text/html", body='<h2>Page not found.</h2>')
        req = requests_for(IOC("2606:4700:4700::1111", "ipv6"), get_method("alienvault.ipv6_to_domain"))[0][1]
        with patch("playwright.sync_api.sync_playwright", self.factory(handle)), self.assertRaises(LookupError) as ctx:
            BrowserTransport(timeout=3).fetch(req)
        self.assertEqual(ctx.exception.status, "not_found")


if __name__ == "__main__":
    unittest.main()
