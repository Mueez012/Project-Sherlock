"""OTX WHOIS email parsing using synthetic rows matching the observed schema."""
from dataclasses import replace
from hashlib import sha256
import json
from pathlib import Path
import unittest

from ioc_hunter.models import IOC
from ioc_hunter.providers import alienvault
from ioc_hunter.transport.models import Document, LookupError


DOMAIN = "python.org"
RELAY_ONE = "first-registration-relay@contact.example.net"
RELAY_TWO = "second-registration-relay@contact.example.net"


def row(key, value, name=None):
    return {"key": key, "name": name or key.strip().replace("_", " ").title(), "value": value}


def document(rows=None, *, count=None, url=None, **changes):
    rows = rows if rows is not None else [
        row("emails", RELAY_ONE, "Emails"),
        row("domain_name", DOMAIN.upper(), "Domain Name"),
        row("emails ", RELAY_TWO, "Emails"),
    ]
    payload = {"data": rows, "count": len(rows) if count is None else count,
               "related": [{"domain": "unrelated.example", "related": "unrelated@evil.example",
                            "related_type": "email"}]}
    values = {"url": url or f"https://otx.alienvault.com/otxapi/indicators/domain/whois/{DOMAIN}",
              "body": json.dumps(payload), "format": "json", "transport": "browser"}
    values.update(changes)
    return Document(**values)


class OTXWhoisTests(unittest.TestCase):
    @property
    def method(self):
        return next(method for method in alienvault.METHODS if method.id == "alienvault.domain_to_email")

    def parse(self, response=None, *, query=None, method=None):
        return alienvault.parse_document(query or IOC(DOMAIN, "domain"), method or self.method,
                                         response or document())

    def test_new_method_uses_observed_browser_route_without_inventing_api_backup(self):
        self.assertEqual(self.method.operation, "whois")
        for key in ("", "synthetic-optional-key"):
            with self.subTest(key_configured=bool(key)):
                routes = alienvault.requests_for(IOC(DOMAIN.upper(), "domain"), self.method, key)
                self.assertEqual(len(routes), 1)
                transport, request = routes[0]
                self.assertEqual(transport, "browser")
                self.assertEqual(request.url, f"https://otx.alienvault.com/indicator/domain/{DOMAIN}")
                self.assertEqual(request.response_paths, (f"/otxapi/indicators/domain/whois/{DOMAIN}",))
                self.assertEqual(request.identity_type, "domain")
                self.assertEqual(request.bootstrap_paths, ("/otxapi/env",))
                self.assertFalse(request.headers)
                self.assertFalse(request.next_selector)
                self.assertFalse(request.result_selector)

    def test_contact_emails_preserve_exact_source_evidence_without_ownership_filtering(self):
        response = document()
        result = self.parse(response, query=IOC(DOMAIN.upper(), "domain"))
        self.assertEqual([observation.ioc.value for observation in result.observations], [RELAY_ONE, RELAY_TWO])
        self.assertTrue(result.complete)
        for observation, index in zip(result.observations, (0, 2)):
            with self.subTest(index=index):
                self.assertEqual(observation.ioc.type, "email")
                self.assertEqual(observation.ioc.source, "alienvault")
                evidence = observation.evidence
                self.assertEqual(evidence.fact_type, "whois_email")
                self.assertEqual(evidence.facts, {"domain": DOMAIN, "email": observation.ioc.value, "field": "emails"})
                self.assertEqual(evidence.locator, f"$.data[{index}].value")
                self.assertEqual(evidence.response_sha256, sha256(response.body.encode()).hexdigest())
                self.assertEqual(evidence.page_url, response.url)
                self.assertEqual(json.loads(evidence.excerpt)["value"], observation.ioc.value)
                self.assertNotIn("confidence", evidence.facts)
                self.assertNotIn("ownership", evidence.facts)

    def test_curated_real_capture_preserves_both_concrete_privacy_contact_addresses(self):
        fixture = Path(__file__).parent / "fixtures" / "otx_whois_python_captured.json"
        response = document(body=fixture.read_text(encoding="utf-8"))
        result = self.parse(response)
        rows = json.loads(response.body)["data"]
        expected = [entry["value"] for entry in rows if entry["key"].strip() == "emails"]
        self.assertEqual(len(expected), 2)
        self.assertEqual([observation.ioc.value for observation in result.observations], expected)
        self.assertTrue(all(email.endswith("@contact.gandi.net") for email in expected))
        self.assertTrue(result.complete)

    def test_only_explicit_email_fields_are_mapped_and_invalid_individuals_are_skipped(self):
        rows = [row("description", "unrelated@evil.example"), row("name", "another@evil.example"),
                row("emails", "REDACTED FOR PRIVACY"), row("emails", None), row("emails", []),
                row("emails", "multiple@@invalid.example"), row("emails", "bad\x00@invalid.example"),
                row("emails", "https://not-an-email.example"), row("email", "VALID@CONTACT.EXAMPLE.NET")]
        result = self.parse(document(rows))
        self.assertEqual([observation.ioc.value for observation in result.observations], ["valid@contact.example.net"])
        self.assertEqual(result.observations[0].evidence.facts["field"], "email")

    def test_explicitly_completed_no_email_is_empty(self):
        for rows in ([], [row("domain_name", DOMAIN)], [row("emails", "REDACTED FOR PRIVACY")]):
            with self.subTest(rows=rows):
                result = self.parse(document(rows))
                self.assertEqual(result.observations, [])
                self.assertTrue(result.complete)
                self.assertEqual(result.reason, "email_unavailable")

    def test_bound_response_path_can_provide_identity_when_domain_row_is_absent(self):
        result = self.parse(document([row("emails", RELAY_ONE)]))
        self.assertEqual(result.observations[0].evidence.facts["domain"], DOMAIN)

    def test_limited_count_retains_known_rows_without_claiming_completion(self):
        result = self.parse(document([row("emails", RELAY_ONE)], count=5))
        self.assertEqual([observation.ioc.value for observation in result.observations], [RELAY_ONE])
        self.assertFalse(result.complete)
        self.assertEqual(result.reason, "whois_result_truncated")
        empty = self.parse(document([], count=1))
        self.assertFalse(empty.complete)
        self.assertEqual(empty.reason, "whois_result_truncated")

    def test_response_host_operation_domain_and_page_are_bound(self):
        urls = (
            f"https://other.example/otxapi/indicators/domain/whois/{DOMAIN}",
            f"http://otx.alienvault.com/otxapi/indicators/domain/whois/{DOMAIN}",
            f"https://otx.alienvault.com/otxapi/indicators/domain/general/{DOMAIN}",
            "https://otx.alienvault.com/otxapi/indicators/domain/whois/other.example",
            f"https://otx.alienvault.com/otxapi/indicators/domain/whois/{DOMAIN}/extra",
            f"https://otx.alienvault.com/otxapi/indicators/domain/whois/{DOMAIN}?page=2",
            f"https://otx.alienvault.com/otxapi/indicators/domain/whois/{DOMAIN}?cursor=next",
        )
        for url in urls:
            with self.subTest(url=url):
                with self.assertRaises(LookupError) as error:
                    self.parse(document(url=url))
                self.assertEqual(error.exception.status, "invalid_response")

    def test_conflicting_domain_name_after_an_email_rejects_whole_response(self):
        for identity in ("other.example", None, [], "not a domain"):
            with self.subTest(identity=identity):
                with self.assertRaises(LookupError):
                    self.parse(document([row("emails", RELAY_ONE), row("domain_name", identity)]))

    def test_malformed_containers_counts_and_rows_are_errors(self):
        payloads = (
            {}, {"data": None, "count": 0}, {"data": {}, "count": 0},
            {"data": [], "count": "0"}, {"data": [], "count": False},
            {"data": [], "count": -1}, {"data": [row("emails", RELAY_ONE)], "count": 0},
            {"data": [None], "count": 1}, {"data": ["email:one@example.net"], "count": 1},
            {"data": [{"key": "emails", "name": "Emails"}], "count": 1},
            {"data": [{"key": None, "name": "Emails", "value": RELAY_ONE}], "count": 1},
            {"data": [{"key": "", "name": "Emails", "value": RELAY_ONE}], "count": 1},
            {"data": [{"key": "emails", "name": None, "value": RELAY_ONE}], "count": 1},
        )
        for payload in payloads:
            with self.subTest(payload=payload):
                with self.assertRaises(LookupError) as error:
                    self.parse(document(body=json.dumps(payload)))
                self.assertEqual(error.exception.status, "parse_error")

    def test_html_loading_or_unrecognized_pages_are_not_empty_whois_successes(self):
        with self.assertRaises(LookupError) as error:
            self.parse(document(format="html", body="<table><tr><td>Emails</td></tr></table>"))
        self.assertEqual(error.exception.status, "parse_error")

    def test_wrong_method_contract_is_rejected(self):
        for method in (replace(self.method, source="virustotal"),
                       replace(self.method, input_type="email"),
                       replace(self.method, output_type="domain")):
            with self.subTest(method=method):
                with self.assertRaises(LookupError):
                    self.parse(method=method)

    def test_duplicate_json_fields_are_rejected_before_parsing(self):
        for body in ('{"data":[],"data":[],"count":0}',
                     '{"data":[{"key":"emails","key":"name","name":"Emails","value":"a@example.net"}],"count":1}'):
            with self.subTest(body=body):
                with self.assertRaises(LookupError) as error:
                    self.parse(document(body=body))
                self.assertEqual(error.exception.status, "parse_error")

    def test_existing_operations_keep_browser_primary_and_configured_api_backup(self):
        for method in alienvault.METHODS:
            if method.operation not in {"dns", "urls", "geo", "url_details"}:
                continue
            value = {"domain": "python.org", "ipv4": "192.0.2.10", "ipv6": "2001:db8::1",
                     "url": "https://www.python.org/path"}[method.input_type]
            with self.subTest(method=method.id):
                routes = alienvault.requests_for(IOC(value, method.input_type), method, "synthetic-key")
                self.assertEqual([transport for transport, _ in routes], ["browser", "http"])
                self.assertEqual(routes[1][1].headers, {"X-OTX-API-KEY": "synthetic-key"})


if __name__ == "__main__":
    unittest.main()
