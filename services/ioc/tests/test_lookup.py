import asyncio
from dataclasses import asdict, replace
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from ioc_hunter import IOC, LookupClient, LookupError, get_method, list_methods, validate_edge
from ioc_hunter.context import Citation, ContextDraft, generated_context
from ioc_hunter.evidence import Observation
from ioc_hunter.metadata import extract_metadata
from ioc_hunter.mcp_server import LookupTools, create_server
from ioc_hunter.models import normalize
from ioc_hunter.ontology import allows_ioc_edge
from ioc_hunter.providers import parse_document, requests_for
from ioc_hunter.storage import EvidenceStore
from ioc_hunter.transport import Document, FetchRequest, allowed_url, check_status
from ioc_hunter.validation import undirected_edge_key

FIXTURES = Path(__file__).parent / "fixtures"

def fixture(name, source="rapiddns", url=None):
    hosts = {"rapiddns": "https://rapiddns.io/subdomain/example.com?page=1",
             "alienvault": "https://otx.alienvault.com/api/v1/indicators/domain/example.com/passive_dns",
             "virustotal": "https://www.virustotal.com/ui/domains/example.com/resolutions"}
    return Document(url or hosts[source], (FIXTURES / name).read_text(encoding="utf-8"),
                    "json" if name.endswith("json") else "html")

class FakeTransport:
    def __init__(self, *results):
        self.results, self.requests = list(results), []
    def fetch(self, request):
        self.requests.append(request)
        if not self.results:
            raise AssertionError("Unexpected extra network call")
        result = self.results.pop(0)
        if isinstance(result, Exception):
            raise result
        return result

class LookupTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = EvidenceStore(self.temp.name)
    def client(self, transport, **kwargs):
        return LookupClient(store=self.store, http=transport, browser=transport, interval=0, **kwargs)
    def test_dns_filters_parent_pollution_and_preserves_provenance(self):
        transport = FakeTransport(fixture("rapiddns.html"))
        client = self.client(transport)
        query = IOC("EXAMPLE.COM", "domain", ["original report"], "cti report")
        result = client.method("rapiddns.domain_to_ipv4")(query)
        self.assertIs(type(result), list)
        self.assertEqual([(x.type, x.value) for x in result], [("ipv4", "192.0.2.10")])
        self.assertEqual(len(result[0].context), 2)
        self.assertEqual(query.value, "EXAMPLE.COM")
        self.assertEqual(query.context, ["original report"])
        record = client.latest_record(query, "rapiddns.domain_to_ipv4")
        self.assertEqual(record["status"], "ok")
        self.assertEqual(record["rejected"][0]["value"], "192.0.2.11")
        self.assertEqual(record["rejected"][0]["reason"], "dns_domain_mismatch")
        self.assertEqual(record["rejected"][0]["details"]["expected_domain"], "example.com")
        self.assertIn("sub.example.com", record["rejected"][0]["message"])
        self.assertTrue(record["evidence"][0]["response_sha256"])
        self.assertNotIn("coverage", record)
        self.assertNotIn("tried_time", record)
    def test_captured_rapiddns_result_table(self):
        client = self.client(FakeTransport(fixture("rapiddns-captured-table.html")))
        query = IOC("example.com", "domain")
        outputs = client.lookup(query, "rapiddns.domain_to_ipv4")
        self.assertEqual(len(outputs), 21)
        self.assertTrue(all('"domain": "example.com"' in c for ioc in outputs for c in ioc.context))
        self.assertTrue(client.latest_record(query, "rapiddns.domain_to_ipv4")["rejected"])

    def test_response_shared_between_output_types(self):
        transport = FakeTransport(fixture("rapiddns.html"))
        client = self.client(transport)
        query = IOC("example.com", "domain")
        client.lookup(query, "rapiddns.domain_to_ipv4")
        output = client.lookup(query, "rapiddns.domain_to_ipv6")
        self.assertEqual([x.value for x in output], ["2001:db8::1"])
        self.assertEqual(len(transport.requests), 1)
        self.assertTrue(client.latest_record(query, "rapiddns.domain_to_ipv6")["cache_hit"])
    def test_reverse_dns_and_undirected_identity(self):
        query = IOC("192.0.2.10", "ipv4")
        client = self.client(FakeTransport(fixture("rapiddns.html")))
        output = client.lookup(query, "rapiddns.ipv4_to_domain")
        self.assertEqual([x.value for x in output], ["example.com"])
        self.assertEqual(undirected_edge_key(query, output[0], "m"), undirected_edge_key(output[0], query, "m"))
    def test_otx_dns_does_not_extract_pulse_indicators(self):
        client = self.client(FakeTransport(fixture("otx_dns.json", "alienvault")))
        outputs = client.lookup(IOC("example.com", "domain"), "alienvault.domain_to_ipv4")
        self.assertEqual([x.value for x in outputs], ["192.0.2.10"])
    def test_vt_dns(self):
        client = self.client(FakeTransport(fixture("vt_dns.json", "virustotal")))
        outputs = client.lookup(IOC("example.com", "domain"), "virustotal.domain_to_ipv4")
        self.assertEqual([x.value for x in outputs], ["192.0.2.10"])
    def test_urls_must_belong_to_query_domain(self):
        client = self.client(FakeTransport(fixture("otx_urls.json", "alienvault")))
        outputs = client.lookup(IOC("example.com", "domain"), "alienvault.domain_to_url")
        self.assertEqual([x.value for x in outputs], ["https://example.com/a"])
    def test_url_host_and_direct_redirect_only(self):
        client = self.client(FakeTransport(fixture("vt_url.json", "virustotal")))
        query = IOC("https://example.com/a", "url")
        domains = client.lookup(query, "virustotal.url_to_domain")
        urls = client.lookup(query, "virustotal.url_to_url")
        self.assertEqual([x.value for x in domains], ["example.com"])
        self.assertEqual({x.value for x in urls}, {"https://linked.example.net/x", "https://redirect.example.net/b"})
        self.assertNotIn("https://final.example.net/c", [x.value for x in urls])
    def test_geo_is_bound_to_ip(self):
        client = self.client(FakeTransport(fixture("vt_geo.json", "virustotal")))
        self.assertEqual(client.lookup(IOC("192.0.2.10", "ipv4"), "virustotal.ipv4_to_geo_location")[0].value, "PK")
        client2 = self.client(FakeTransport(fixture("vt_geo.json", "virustotal")))
        self.assertEqual(client2.lookup(IOC("192.0.2.11", "ipv4"), "virustotal.ipv4_to_geo_location"), [])
    def test_loading_shell_not_empty_and_api_fallback(self):
        loading = Document("https://otx.alienvault.com/indicator/domain/example.com", "Loading...", "html")
        transport = FakeTransport(loading, fixture("otx_dns.json", "alienvault"))
        client = self.client(transport, api_keys={"alienvault": "test-secret"})
        result = client.lookup(IOC("example.com", "domain"), "alienvault.domain_to_ipv4")
        self.assertEqual(len(result), 1)
        self.assertEqual(transport.requests[1].headers["X-OTX-API-KEY"], "test-secret")
        record = client.latest_record(IOC("example.com", "domain"), "alienvault.domain_to_ipv4")
        self.assertEqual(record["transport_errors"][0]["status"], "loading_page")
        self.assertNotIn("test-secret", json.dumps(record))
    def test_failed_call_raises_and_keeps_diagnostics(self):
        challenge = Document("https://rapiddns.io/subdomain/example.com", "<h1>captcha</h1>", "html")
        client = self.client(FakeTransport(challenge, challenge))
        with self.assertRaises(LookupError) as ctx:
            client.lookup(IOC("example.com", "domain"), "rapiddns.domain_to_ipv4")
        self.assertEqual(ctx.exception.status, "challenge")
        self.assertEqual(self.store.get_record(ctx.exception.lookup_id)["status"], "challenge")
    def test_empty_array_is_successful_empty(self):
        doc = Document("https://otx.alienvault.com/api/v1/indicators/domain/example.com/passive_dns", '{"passive_dns":[]}', "json")
        client = self.client(FakeTransport(doc))
        query = IOC("example.com", "domain")
        self.assertEqual(client.lookup(query, "alienvault.domain_to_ipv4"), [])
        self.assertEqual(client.latest_record(query, "alienvault.domain_to_ipv4")["status"], "empty")
    def test_unsupported_method_makes_no_request(self):
        transport = FakeTransport()
        client = self.client(transport)
        with self.assertRaises(LookupError) as ctx:
            client.lookup(IOC("example.com", "domain"), "rapiddns.domain_to_url")
        self.assertEqual(ctx.exception.status, "unsupported_method")
        self.assertEqual(transport.requests, [])
    def test_metadata_requires_labelled_fields(self):
        outputs = extract_metadata({"email": "Analyst@EXAMPLE.COM", "cve": "cve-2024-12345", "filename": "payload.exe",
                                    "port": 443, "protocol": "TCP", "country_code": "pk", "random_number": 123}, source="fixture")
        self.assertEqual({(x.type, x.value) for x in outputs}, {("email", "analyst@example.com"), ("cve", "CVE-2024-12345"),
                         ("filename", "payload.exe"), ("port", "443"), ("protocol", "tcp"), ("geo_location", "PK")})
        self.assertEqual(extract_metadata({"port": True, "filename": "../bad", "protocol": "nonsense", "country_code": "invalid"}, source="fixture"), [])
    def test_llm_context_does_not_override_validation(self):
        seen = []
        def generate(request):
            seen.append(request)
            ev = request["evidence"][0]
            return ContextDraft("A DNS observation was returned.", (Citation(ev["id"], ev["text"]),))
        client = self.client(FakeTransport(fixture("rapiddns.html")), context_generator=generate)
        result = client.lookup(IOC("example.com", "domain"), "rapiddns.domain_to_ipv4")
        self.assertEqual(len(result), 1)
        self.assertEqual(len(seen), 1)
        self.assertTrue(result[0].context[-1].startswith("[LLM summary;"))
        self.assertNotIn("instructions", seen[0]["evidence"][0])
    def test_invalid_llm_citation_retains_raw_context(self):
        client = self.client(FakeTransport(fixture("rapiddns.html")), context_generator=lambda r: ContextDraft("invented", (Citation("fake", "fake"),)))
        result = client.lookup(IOC("example.com", "domain"), "rapiddns.domain_to_ipv4")
        self.assertEqual(len(result[0].context), 2)
    def test_page_limit_reports_partial(self):
        doc = fixture("rapiddns.html")
        doc.body += '<a rel="next" href="?page=2">Next</a>'
        client = self.client(FakeTransport(doc), max_pages=1)
        query = IOC("example.com", "domain")
        self.assertTrue(client.lookup(query, "rapiddns.domain_to_ipv4"))
        self.assertFalse(client.latest_record(query, "rapiddns.domain_to_ipv4")["complete"])
    def test_pagination_reads_second_page(self):
        first = fixture("rapiddns.html")
        first.body += '<a rel="next" href="?page=2">Next</a>'
        second = fixture("rapiddns.html", url="https://rapiddns.io/subdomain/example.com?page=2")
        second.body = second.body.replace("192.0.2.10", "192.0.2.20")
        transport = FakeTransport(first, second)
        outputs = self.client(transport).lookup(IOC("example.com", "domain"), "rapiddns.domain_to_ipv4")
        self.assertEqual({x.value for x in outputs}, {"192.0.2.10", "192.0.2.20"})
        self.assertTrue(transport.requests[1].url.endswith("page=2"))
    def test_max_outputs_and_guest_limits_are_reported(self):
        doc = fixture("rapiddns.html")
        doc.body = doc.body.replace("sub.example.com", "example.com") + "Limited Access"
        client = self.client(FakeTransport(doc), max_outputs=1)
        query = IOC("example.com", "domain")
        self.assertEqual(len(client.lookup(query, "rapiddns.domain_to_ipv4")), 1)
        self.assertEqual(client.latest_record(query, "rapiddns.domain_to_ipv4")["status"], "partial")
    def test_daily_budget_and_rate_limit_do_not_fallback(self):
        transport = FakeTransport(LookupError("rate_limited", "quota", retry_after=120))
        client = self.client(transport, api_keys={"alienvault": "key"})
        with self.assertRaises(LookupError):
            client.lookup(IOC("example.com", "domain"), "alienvault.domain_to_ipv4")
        self.assertEqual(len(transport.requests), 1)
        self.store.consume_budget("test", 1)
        with self.assertRaises(LookupError):
            self.store.consume_budget("test", 1)
    def test_cache_expiry_fetches_again(self):
        transport = FakeTransport(fixture("rapiddns.html"), fixture("rapiddns.html"))
        client = self.client(transport, cache_ttl=0)
        for _ in range(2):
            client.lookup(IOC("example.com", "domain"), "rapiddns.domain_to_ipv4")
        self.assertEqual(len(transport.requests), 2)
    def test_mcp_and_python_results_match(self):
        client = self.client(FakeTransport(fixture("rapiddns.html")))
        query = IOC("example.com", "domain")
        direct = client.lookup(query, "rapiddns.domain_to_ipv4")
        tools = LookupTools(client)
        self.assertEqual(tools.lookup_ioc(query.value, query.type, "rapiddns.domain_to_ipv4"), [asdict(x) for x in direct])
        record = tools.get_latest_lookup(query.value, query.type, "rapiddns.domain_to_ipv4")
        self.assertIn("raw_responses", tools.get_lookup_evidence(record["id"], True))
    def test_real_mcp_registration_and_tool_call(self):
        try:
            import mcp
        except ImportError:
            self.skipTest("Optional MCP SDK not installed")
        class ThreadCheckedTransport(FakeTransport):
            def fetch(self, request):
                try:
                    asyncio.get_running_loop()
                except RuntimeError:
                    return super().fetch(request)
                raise AssertionError("Browser work must run outside the MCP event loop")
        server = create_server(self.client(ThreadCheckedTransport(fixture("rapiddns.html"))))
        async def run():
            names = {t.name for t in await server.list_tools()}
            self.assertIn("lookup_ioc", names)
            result = await server.call_tool("lookup_ioc", {"value": "example.com", "ioc_type": "domain", "method_id": "rapiddns.domain_to_ipv4"})
            self.assertIn("192.0.2.10", str(result))
        asyncio.run(run())

class ValidationTests(unittest.TestCase):
    def setUp(self):
        self.query = IOC("example.com", "domain")
        self.method = get_method("rapiddns.domain_to_ipv4")
        self.observation = parse_document(self.query, self.method, fixture("rapiddns.html")).observations[0]
    def test_wrong_query_wrong_source_and_fabricated_target_rejected(self):
        obs = self.observation
        for evidence in (replace(obs.evidence, query_value="other.example.net"), replace(obs.evidence, source="virustotal"),
                         replace(obs.evidence, facts={"domain": "sub.example.com", "ip": "192.0.2.10", "record_type": "A"}),
                         replace(obs.evidence, facts={"domain": "example.com", "ip": "192.0.2.10", "record_type": "MX"})):
            self.assertFalse(validate_edge(self.query, obs.ioc, self.method, evidence).accepted)
        self.assertFalse(validate_edge(self.query, IOC("203.0.113.1", "ipv4"), self.method, obs.evidence).accepted)
    def test_type_allowlist_is_not_evidence(self):
        obs = self.observation
        self.assertTrue(allows_ioc_edge("domain", "ipv4"))
        self.assertFalse(validate_edge(self.query, obs.ioc, self.method, replace(obs.evidence, fact_type="co_occurrence")).accepted)
    def test_forbidden_pairs_absent_from_registry(self):
        for left, right in [("md5", "ipv4"), ("sha256", "domain"), ("ipv4", "port"), ("domain", "domain"), ("url", "ipv4")]:
            self.assertFalse(allows_ioc_edge(left, right))
            self.assertFalse(any(m.input_type == left and m.output_type == right for m in list_methods()))
    def test_method_types_and_query_echo(self):
        obs = self.observation
        self.assertFalse(validate_edge(self.query, IOC("2001:db8::1", "ipv6"), self.method, obs.evidence).accepted)
    def test_normalization_and_provider_only_targets(self):
        self.assertEqual(normalize("url", "https://EXAMPLE.COM/Upper?Query=X"), "https://example.com/Upper?Query=X")
        self.assertEqual(normalize("ipv6", "2001:0db8::1"), "2001:db8::1")
        for kind, value in [("domain", "192.0.2.1"), ("ipv4", "2001:db8::1"), ("port", "65536"), ("url", "https://user:pass@example.com")]:
            with self.assertRaises(ValueError):
                normalize(kind, value)
        self.assertFalse(allowed_url("virustotal", "https://example.com"))
        self.assertFalse(allowed_url("virustotal", "https://www.virustotal.com.evil.example"))
    def test_request_construction_uses_provider_urls_not_ioc_url(self):
        for method_id, ioc in [("virustotal.url_to_domain", IOC("https://example.com/a?x=1", "url")),
                               ("alienvault.domain_to_url", self.query)]:
            method = get_method(method_id)
            routes = requests_for(ioc, method, "key")
            self.assertEqual(routes[0][0], "browser")
            self.assertTrue(all(allowed_url(method.source, req.url) for _, req in routes))
            self.assertEqual(routes[-1][0], "http")
    def test_vt_premium_api_is_not_a_free_fallback(self):
        routes = requests_for(self.query, get_method("virustotal.domain_to_url"), "key")
        self.assertEqual([transport for transport, _ in routes], ["browser"])
    def test_pagination_cannot_change_query(self):
        doc = fixture("vt_dns.json", "virustotal")
        data = json.loads(doc.body)
        data["links"] = {"next": "https://www.virustotal.com/ui/domains/other.example.net/resolutions"}
        doc.body = json.dumps(data)
        with self.assertRaises(LookupError) as ctx:
            parse_document(self.query, get_method("virustotal.domain_to_ipv4"), doc)
        self.assertEqual(ctx.exception.status, "unsafe_pagination")
    def test_extended_report_extraction_is_opt_in(self):
        from ioc_hunter.interactive_extraction import find_sentence_iocs
        sentences = ["Contact Analyst@example.com about CVE-2024-12345."]
        baseline = find_sentence_iocs(sentences)[0]
        extended = find_sentence_iocs(sentences, extended=True)[0]
        self.assertNotIn(("email", "analyst@example.com"), baseline)
        self.assertIn(("email", "analyst@example.com"), extended)
        self.assertIn(("cve", "CVE-2024-12345"), extended)
    def test_malformed_dns_schema_is_not_an_empty_result(self):
        doc = Document("https://otx.alienvault.com/api/v1/indicators/domain/example.com/passive_dns", '{"passive_dns": {}}', "json")
        with self.assertRaises(LookupError) as ctx:
            parse_document(self.query, get_method("alienvault.domain_to_ipv4"), doc)
        self.assertEqual(ctx.exception.status, "parse_error")

    def test_loading_table_is_not_successful_empty(self):
        html = '<table><tr><th>Domain</th><th>Address</th><th>Type</th></tr><tr><td colspan="3">Loading...</td></tr></table>'
        with self.assertRaises(LookupError) as ctx:
            parse_document(self.query, self.method, Document("https://rapiddns.io/subdomain/example.com", html, "html"))
        self.assertEqual(ctx.exception.status, "loading_page")

    def test_error_status(self):
        with self.assertRaises(LookupError) as ctx:
            check_status(429, {"Retry-After": "120"})
        self.assertEqual(ctx.exception.retry_after, 120)

if __name__ == "__main__":
    unittest.main()
