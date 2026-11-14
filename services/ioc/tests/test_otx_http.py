"""Offline contracts for OTX's captured URL HTTP-header response."""
import json
from pathlib import Path
import unittest
from urllib.parse import quote

from ioc_hunter import IOC
from ioc_hunter.method_spec import supported_method
from ioc_hunter.providers.common import ObservationBuilder
from ioc_hunter.providers.otx_http import parse_http_scans
from ioc_hunter.transport import Document, LookupError


METHOD = supported_method("alienvault", input_type="url", output_type="url", operation="http_scans")
QUERY = "http://github.com/"


class OTXHTTPTests(unittest.TestCase):
    def document(self, data, *, query=QUERY, url=None):
        return Document(url or "https://otx.alienvault.com/otxapi/indicators/url/http_scans/" + quote(query, safe=""),
                        json.dumps(data), "json", "browser")

    def builder(self, data, *, query=QUERY, url=None):
        return ObservationBuilder(IOC(query, "url", ["original context"], "cti report"), METHOD,
                                  self.document(data, query=query, url=url))

    def rows(self, header, *extra):
        rows = [{"key": "header", "name": "Header", "value": header}, *extra]
        return {"data": rows, "count": len(rows)}

    def test_captured_github_header_has_one_direct_https_redirect(self):
        fixture = Path(__file__).parent / "fixtures" / "otx_http_github_captured.json"
        document = self.document({})
        document.body = fixture.read_text(encoding="utf-8")
        builder = ObservationBuilder(IOC(QUERY, "url"), METHOD, document)
        result = parse_http_scans(builder)
        self.assertEqual([item.ioc.value for item in result.observations], ["https://github.com/"])
        evidence = result.observations[0].evidence
        self.assertEqual(evidence.locator, "$.data[0].value")
        self.assertEqual(evidence.facts, {"from_url": QUERY, "to_url": "https://github.com/", "kind": "redirect"})
        self.assertTrue(evidence.response_sha256)
        self.assertTrue(result.complete)

    def test_relative_location_and_status_variants(self):
        query = "https://github.com/Old/Path?Case=Yes"
        for status in (301, 302, 303, 307, 308):
            with self.subTest(status=status):
                result = parse_http_scans(self.builder(self.rows(
                    f"HTTP/1.1 {status} Redirect\r\nContent-Length: 0\r\nlOcAtIoN: ../New?Q=Mixed\r\n\r\n"), query=query))
                self.assertEqual([item.ioc.value for item in result.observations],
                                 ["https://github.com/New?Q=Mixed"])

    def test_flattened_header_location_before_another_header(self):
        result = parse_http_scans(self.builder(self.rows(
            "HTTP/2 302 Found Location: /Next?Case=Yes Content-Type: text/html")))
        self.assertEqual([item.ioc.value for item in result.observations], ["http://github.com/Next?Case=Yes"])

    def test_each_query_bound_header_row_retains_its_own_redirect(self):
        first = self.rows("HTTP/1.1 301 Location: /One")["data"][0]
        second = self.rows("HTTP/1.1 302 Location: /Two")["data"][0]
        result = parse_http_scans(self.builder({"data": [first, second, first], "count": 3}))
        self.assertEqual([item.ioc.value for item in result.observations],
                         ["http://github.com/One", "http://github.com/Two", "http://github.com/One"])
        self.assertEqual([item.evidence.locator for item in result.observations],
                         ["$.data[0].value", "$.data[1].value", "$.data[2].value"])
        self.assertTrue(result.complete)

    def test_valid_uri_apostrophes_are_preserved(self):
        for location, expected in (("https://github.com/O'Reilly", "https://github.com/O'Reilly"),
                                   ("/O'Reilly", "http://github.com/O'Reilly")):
            with self.subTest(location=location):
                result = parse_http_scans(self.builder(self.rows("HTTP/1.1 301 Location: " + location)))
                self.assertEqual([item.ioc.value for item in result.observations], [expected])

    def test_nonredirect_missing_location_and_empty_rows_are_completed_empty(self):
        for data in ({"data": [], "count": 0}, self.rows("HTTP/1.1 200 OK Location: https://other.example/"),
                     self.rows("HTTP/1.1 304 Not Modified Location: /next"),
                     self.rows("HTTP/1.1 301 Moved Permanently Content length: 0")):
            with self.subTest(data=data):
                result = parse_http_scans(self.builder(data))
                self.assertFalse(result.observations)
                self.assertTrue(result.complete)
                self.assertEqual(result.reason, "redirect_unavailable")

    def test_body_and_outgoing_link_noise_never_creates_a_redirect(self):
        extra = {"key": "body", "name": "Body", "value": 'Location: https://noise.example/ <a href="https://link.example/">x</a>'}
        for data in (self.rows("HTTP/1.1 301 Moved Permanently", extra),
                     self.rows("HTTP/1.1 301 Moved Permanently\r\nServer: nginx\r\n\r\nLocation: https://noise.example/"),
                     {"data": [extra], "count": 1}):
            with self.subTest(data=data):
                self.assertFalse(parse_http_scans(self.builder(data)).observations)

    def test_duplicate_or_malformed_location_is_a_parse_error(self):
        for header in ("HTTP/1.1 301 Moved Location: /one Location: /two",
                       "HTTP/1.1 301 Moved\r\nLocation: /one\r\nLocation: /two",
                       "HTTP/1.1 301 Moved Location:", "HTTP/1.1 301 Moved Location: /one extra words",
                       "HTTP/1.1 301 Moved Location: javascript:alert(1)",
                       "HTTP/1.1 301 Moved Location: https://user:password@other.example/",
                       'HTTP/1.1 301 Moved Location: "https://other.example/"',
                       "HTTP/1.1 301 Moved\rLocation: /one", "Location: https://other.example/", ""):
            with self.subTest(header=header):
                builder = self.builder(self.rows(header))
                with self.assertRaises(LookupError) as failure:
                    parse_http_scans(builder)
                self.assertEqual(failure.exception.status, "parse_error")
                self.assertFalse(builder.result.observations)

    def test_url_identity_decodes_once_and_preserves_path_query_and_trailing_slash(self):
        query = "http://github.com/Case/%2F?Key=Value"
        result = parse_http_scans(self.builder(self.rows("HTTP/1.1 302 Found Location: /New"), query=query))
        self.assertEqual(result.observations[0].evidence.query_value, query)
        wrong = ("http://github.com/case/%2F?Key=Value", "http://github.com/Case/%2F?Key=value",
                 "http://github.com/Case/%2F?Key=Value/", "http://other.example/Case/%2F?Key=Value")
        for response_query in wrong:
            with self.subTest(response_query=response_query):
                url = self.document({}, query=response_query).url
                with self.assertRaises(LookupError) as failure:
                    parse_http_scans(self.builder(self.rows("HTTP/1.1 302 Found Location: /New"), query=query, url=url))
                self.assertEqual(failure.exception.status, "invalid_response")
        for response_query in ("http://github.com", "http://github.com//"):
            with self.subTest(response_query=response_query):
                with self.assertRaises(LookupError):
                    parse_http_scans(self.builder(self.rows("HTTP/1.1 301 Location: /New"),
                                                 url=self.document({}, query=response_query).url))
        double_encoded = "https://otx.alienvault.com/otxapi/indicators/url/http_scans/" + quote(quote(QUERY, safe=""), safe="")
        with self.assertRaises(LookupError):
            parse_http_scans(self.builder(self.rows("HTTP/1.1 301 Location: /New"), url=double_encoded))

    def test_wrong_source_operation_and_continuation_are_rejected(self):
        valid = self.document({}).url
        for url in (valid.replace("otx.alienvault.com", "unrelated.example"),
                    valid.replace("/http_scans/", "/general/"), valid + "?page=2", valid + "?cursor=next"):
            with self.subTest(url=url):
                with self.assertRaises(LookupError) as failure:
                    parse_http_scans(self.builder(self.rows("HTTP/1.1 301 Location: /New"), url=url))
                self.assertEqual(failure.exception.status, "invalid_response")

    def test_schema_errors_never_become_completed_empty(self):
        valid = self.rows("HTTP/1.1 301 Location: /New")
        for data in ({}, {"data": [], "count": True}, {"data": {}, "count": 0},
                     {"data": [], "count": -1}, {**valid, "count": 0},
                     {"data": [{"key": "header", "name": "Header", "value": 301}], "count": 1},
                     {"data": [valid["data"][0], {"key": "broken"}], "count": 2}):
            with self.subTest(data=data):
                builder = self.builder(data)
                with self.assertRaises(LookupError) as failure:
                    parse_http_scans(builder)
                self.assertEqual(failure.exception.status, "parse_error")
                self.assertFalse(builder.result.observations)

    def test_more_rows_than_captured_remains_partial(self):
        for data in ({**self.rows("HTTP/1.1 301 Location: /New"), "count": 2}, {"data": [], "count": 1}):
            with self.subTest(data=data):
                result = parse_http_scans(self.builder(data))
                self.assertFalse(result.complete)
                self.assertEqual(result.reason, "http_scan_result_truncated")


if __name__ == "__main__":
    unittest.main()
