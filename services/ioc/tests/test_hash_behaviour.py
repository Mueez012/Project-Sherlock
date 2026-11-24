"""Offline VirusTotal hash-family routing and behavior parsing contracts."""
import json
from dataclasses import replace
from io import BytesIO
import tempfile
import unittest
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.parse import urlsplit

from ioc_hunter import IOC, LookupClient, validate_edge
from ioc_hunter.providers import virustotal
from ioc_hunter.storage import EvidenceStore
from ioc_hunter.transport import Document, HTTPTransport, LookupError


HASHES = {"md5": "a" * 32, "sha1": "b" * 40, "sha256": "c" * 64}


class UnavailableBrowser:
    """A bounded browser failure for tests exercising the optional HTTP backup."""
    offline = True

    def fetch(self, request):
        raise LookupError("not_found", "Synthetic unavailable report page")


def browser_document(value, attributes=None, *, canonical_hash=None, **changes):
    canonical_hash = canonical_hash or (value if len(value) == 64 else HASHES["sha256"])
    response_url = f"https://www.virustotal.com/ui/files/{canonical_hash}/behaviours"
    values = {
        "url": response_url, "format": "json", "transport": "browser",
        "body": json.dumps({"data": [{
            "id": canonical_hash + "_Synthetic sandbox", "type": "file_behaviour",
            "attributes": attributes if attributes is not None else {"command_executions": ["cmd.exe /c whoami"]},
        }], "links": {"self": response_url}}),
        "diagnostics": {
            "request_url": f"https://www.virustotal.com/gui/file/{value}/behavior",
            "page_url": f"https://www.virustotal.com/gui/file/{canonical_hash}",
        },
    }
    values.update(changes)
    return Document(**values)


class HashBehaviourTests(unittest.TestCase):
    def method(self, kind):
        return next(method for method in virustotal.METHODS
                    if method.id == f"virustotal.{kind}_to_command_api")

    def document(self, kind, data, **changes):
        values = {
            "url": f"https://www.virustotal.com/api/v3/files/{HASHES[kind]}/behaviour_summary",
            "body": json.dumps(data), "format": "json",
        }
        values.update(changes)
        return Document(**values)

    def test_all_hash_types_share_browser_primary_and_optional_api_operation(self):
        for kind, value in HASHES.items():
            with self.subTest(kind=kind):
                method = self.method(kind)
                self.assertEqual(method.operation, "file_behavior")
                routes = virustotal.requests_for(IOC(value.upper(), kind), method, "synthetic-key")
                self.assertEqual(len(routes), 2)
                primary_transport, primary = routes[0]
                self.assertEqual(primary_transport, "browser")
                self.assertEqual(primary.url, f"https://www.virustotal.com/gui/file/{value}/behavior")
                self.assertIn(f"/ui/files/{value}/behaviours", primary.response_paths)
                self.assertIn("/ui/files/{page_id}/behaviours", primary.response_paths)
                self.assertFalse(primary.headers)
                self.assertEqual(primary.integration_version, "3")
                transport, request = routes[1]
                self.assertEqual(transport, "http")
                self.assertEqual(request.url,
                                 f"https://www.virustotal.com/api/v3/files/{value}/behaviour_summary")
                self.assertEqual(request.headers, {"x-apikey": "synthetic-key"})
                self.assertEqual(request.response_paths, ())

    def test_keyless_browser_route_is_available_for_every_hash_type(self):
        for kind, value in HASHES.items():
            with self.subTest(kind=kind):
                routes = virustotal.requests_for(IOC(value, kind), self.method(kind))
                self.assertEqual(len(routes), 1)
                self.assertEqual(routes[0][0], "browser")
                self.assertEqual(routes[0][1].url, f"https://www.virustotal.com/gui/file/{value}/behavior")

    def test_shared_parser_extracts_only_documented_command_api_fields(self):
        # Explicitly synthetic documentation-shaped data; no live access is implied.
        data = {"data": {
            "command_executions": ['  cmd.exe /c "Echo Mixed  Case"  ', "\n\t"],
            "calls_highlighted": ["GetTickCount"],
            "invokes": ["java.lang.Runtime.exec"],
            "files_opened": ["unrelated.exe"], "text_highlighted": ["not-a-command"],
        }}
        for kind, value in HASHES.items():
            with self.subTest(kind=kind):
                query = IOC(value, kind, ["Original report context"], "cti report")
                original_context = list(query.context)
                document = self.document(kind, data)
                result = virustotal.parse_document(query, self.method(kind), document)
                self.assertEqual([observation.ioc.value for observation in result.observations],
                                 ['cmd.exe /c "Echo Mixed  Case"', "GetTickCount", "java.lang.Runtime.exec"])
                self.assertTrue(result.complete)
                self.assertEqual(result.next_url, "")
                self.assertEqual(query.context, original_context)
                for observation in result.observations:
                    self.assertEqual(observation.ioc.type, "command_api")
                    self.assertEqual(observation.ioc.source, "virustotal")
                    self.assertEqual(observation.evidence.query_type, kind)
                    self.assertEqual(observation.evidence.query_value, value)
                    self.assertEqual(observation.evidence.operation, "file_behavior")
                    self.assertTrue(observation.evidence.locator.startswith("$.data."))
                    self.assertTrue(observation.evidence.response_sha256)

    def test_empty_or_absent_command_fields_are_completed_empty(self):
        for attributes in ({}, {"command_executions": [], "calls_highlighted": [], "invokes": []},
                           {"files_opened": ["sample.exe"]}):
            with self.subTest(attributes=attributes):
                result = virustotal.parse_document(IOC(HASHES["sha256"], "sha256"),
                                                   self.method("sha256"),
                                                   self.document("sha256", {"data": attributes}))
                self.assertEqual(result.observations, [])
                self.assertTrue(result.complete)

    def test_wrong_hash_host_and_operation_are_rejected(self):
        for url in (f"https://www.virustotal.com/api/v3/files/{'d' * 64}/behaviour_summary",
                    f"https://unrelated.example/api/v3/files/{HASHES['sha256']}/behaviour_summary",
                    f"https://www.virustotal.com/api/v3/files/{HASHES['sha256']}"):
            with self.subTest(url=url):
                with self.assertRaises(LookupError) as failure:
                    virustotal.parse_document(IOC(HASHES["sha256"], "sha256"), self.method("sha256"),
                                              self.document("sha256", {"data": {}}, url=url))
                self.assertEqual(failure.exception.status, "invalid_response")

    def test_malformed_summary_stays_a_parse_error(self):
        for data in ({}, {"data": []}, {"data": {"command_executions": "cmd.exe"}},
                     {"data": {"calls_highlighted": [17]}}, {"data": {"invokes": None}},
                     {"data": {"attributes": {"command_executions": ["cmd.exe"]}}},
                     {"data": {"id": HASHES["sha256"], "type": "file", "attributes": {}}}):
            with self.subTest(data=data):
                with self.assertRaises(LookupError) as failure:
                    virustotal.parse_document(IOC(HASHES["sha256"], "sha256"), self.method("sha256"),
                                              self.document("sha256", data))
                self.assertEqual(failure.exception.status, "parse_error")
        for changes in ({"body": "not-json"}, {"format": "html", "body": "Loading..."}):
            with self.subTest(changes=changes):
                with self.assertRaises(LookupError) as failure:
                    virustotal.parse_document(IOC(HASHES["sha256"], "sha256"), self.method("sha256"),
                                              self.document("sha256", {"data": {}}, **changes))
                self.assertEqual(failure.exception.status, "parse_error")

    def test_method_proof_rejects_wrong_source_query_field_and_output(self):
        query = IOC(HASHES["sha256"], "sha256")
        method = self.method("sha256")
        observation = virustotal.parse_document(query, method, self.document("sha256", {
            "data": {"command_executions": ["cmd.exe /c whoami"]},
        })).observations[0]
        evidence = observation.evidence
        self.assertTrue(validate_edge(query, observation.ioc, method, evidence).accepted)
        cases = (
            (replace(evidence, source="alienvault"), "method_evidence_mismatch"),
            (replace(evidence, query_value="d" * 64), "wrong_query"),
            (replace(evidence, facts={"field": "files_opened", "value": observation.ioc.value}),
             "relationship_not_supported_by_fields"),
            (replace(evidence, facts={"field": "command_executions", "value": "different command"}),
             "relationship_not_supported_by_fields"),
        )
        for changed_evidence, reason in cases:
            with self.subTest(reason=reason, facts=changed_evidence.facts):
                verdict = validate_edge(query, observation.ioc, method, changed_evidence)
                self.assertFalse(verdict.accepted)
                self.assertEqual(verdict.reason, reason)

    def test_browser_reports_bind_original_alias_through_actual_navigation(self):
        for kind, value in HASHES.items():
            with self.subTest(kind=kind):
                query, method = IOC(value, kind), self.method(kind)
                document = browser_document(value, {"calls_highlighted": [" GetTickCount "]})
                parsed = virustotal.parse_document(query, method, document)
                self.assertEqual([observation.ioc.value for observation in parsed.observations], ["GetTickCount"])
                evidence = parsed.observations[0].evidence
                self.assertEqual(evidence.locator, "$.data[0].attributes.calls_highlighted[0]")
                self.assertEqual(evidence.query_value, value)
                self.assertTrue(validate_edge(query, parsed.observations[0].ioc, method, evidence).accepted)

    def test_alias_response_needs_the_original_navigation_and_exact_current_page(self):
        query, method = IOC(HASHES["md5"], "md5"), self.method("md5")
        valid = browser_document(query.value)
        cases = ({}, {**valid.diagnostics, "request_url": f"https://www.virustotal.com/gui/file/{'d' * 32}/behavior"},
                 {**valid.diagnostics, "page_url": f"https://www.virustotal.com/gui/file/{'d' * 64}"},
                 {**valid.diagnostics, "page_url": f"https://unrelated.example/gui/file/{HASHES['sha256']}"},
                 {**valid.diagnostics, "page_url": f"https://www.virustotal.com/gui/file/{HASHES['sha256']}/details"})
        for diagnostics in cases:
            with self.subTest(diagnostics=diagnostics):
                with self.assertRaises(LookupError) as failure:
                    virustotal.parse_document(query, method, replace(valid, diagnostics=diagnostics))
                self.assertEqual(failure.exception.status, "invalid_response")

    def test_browser_rejects_other_sample_records_and_wrong_envelopes(self):
        query, method = IOC(HASHES["sha256"], "sha256"), self.method("sha256")
        document = browser_document(query.value)
        valid = json.loads(document.body)
        wrong_sample = json.loads(document.body)
        wrong_sample["data"][0]["id"] = "d" * 64 + "_Synthetic sandbox"
        wrong_type = json.loads(document.body)
        wrong_type["data"][0]["type"] = "file"
        missing_fields = json.loads(document.body)
        del missing_fields["data"][0]["attributes"]
        cases = ((wrong_sample, "invalid_response"), (wrong_type, "parse_error"),
                 (missing_fields, "parse_error"), ({"data": valid["data"][0]}, "parse_error"),
                 ({"data": [{"id": "invalid_hash_Sandbox", "type": "file_behaviour", "attributes": {}}]}, "parse_error"))
        for data, status in cases:
            with self.subTest(data=data):
                with self.assertRaises(LookupError) as failure:
                    virustotal.parse_document(query, method, replace(document, body=json.dumps(data)))
                self.assertEqual(failure.exception.status, status)

    def test_browser_empty_list_is_empty_and_later_reports_stay_paginated(self):
        query, method = IOC(HASHES["sha256"], "sha256"), self.method("sha256")
        document = browser_document(query.value, body='{"data":[],"meta":{"count":0}}')
        self.assertEqual(virustotal.parse_document(query, method, document).observations, [])
        document = browser_document(query.value)
        data = json.loads(document.body)
        data["links"]["next"] = document.url + "?cursor=next"
        parsed = virustotal.parse_document(query, method, replace(document, body=json.dumps(data)))
        self.assertEqual(parsed.next_url, document.url + "?cursor=next")


class HashBehaviourLookupTests(unittest.TestCase):
    def test_each_hash_api_backup_uses_one_request_and_existing_method_validator(self):
        import tempfile
        from ioc_hunter import LookupClient
        from ioc_hunter.storage import EvidenceStore

        class OfflineHTTP:
            offline = True

            def __init__(self):
                self.requests = []

            def fetch(self, request):
                self.requests.append(request)
                return Document(request.url, json.dumps({"data": {
                    "command_executions": ["cmd.exe /c whoami", "cmd.exe /c whoami"],
                    "calls_highlighted": ["GetTickCount"],
                }}), "json")

        for kind, value in HASHES.items():
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                transport = OfflineHTTP()
                client = LookupClient(store=EvidenceStore(directory), http=transport,
                                      browser=UnavailableBrowser(),
                                      api_keys={"virustotal": "synthetic-key"}, interval=0)
                receipt = client.lookup_detailed(IOC(value, kind),
                                                 f"virustotal.{kind}_to_command_api")
                self.assertEqual([ioc.value for ioc in receipt.outputs],
                                 ["cmd.exe /c whoami", "GetTickCount"])
                self.assertEqual(len(transport.requests), 1)
                self.assertIn(f"/files/{value}/behaviour_summary", transport.requests[0].url)
                self.assertEqual(receipt.status, "ok")
                self.assertEqual(len(receipt.accepted), 3)
                self.assertFalse(receipt.rejected)
                self.assertEqual(receipt.input_ioc.type, kind)
                self.assertNotIn("synthetic-key", json.dumps(receipt.to_dict()))

    def test_keyless_browser_access_is_visible_in_discovery_and_receipts(self):
        import tempfile
        from ioc_hunter import LookupClient
        from ioc_hunter.methods import get_method, method_status
        from ioc_hunter.storage import EvidenceStore

        status = method_status(get_method("virustotal.md5_to_command_api"), api_keys={})
        self.assertEqual(status["primary_transport"], "browser")
        self.assertFalse(status.get("api_key_required", False))
        self.assertFalse(status["api_key_configured"])
        class OfflineBrowser:
            offline = True

            def __init__(self):
                self.requests = []

            def fetch(self, request):
                self.requests.append(request)
                value = urlsplit(request.url).path.strip("/").split("/")[2]
                return browser_document(value)

        with tempfile.TemporaryDirectory() as directory:
            browser = OfflineBrowser()
            client = LookupClient(store=EvidenceStore(directory), browser=browser, api_keys={})
            for kind, value in HASHES.items():
                receipt = client.lookup_detailed(IOC(value, kind), f"virustotal.{kind}_to_command_api")
                self.assertEqual(receipt.status, "ok")
                self.assertEqual([ioc.value for ioc in receipt.outputs], ["cmd.exe /c whoami"])
                self.assertFalse(receipt.transport_errors)
            self.assertEqual(len(browser.requests), 3)

    def test_normalized_hash_reuses_cache_without_mutating_the_input(self):
        class OfflineHTTP:
            offline = True

            def __init__(self):
                self.requests = []

            def fetch(self, request):
                self.requests.append(request)
                return Document(request.url, '{"data":{"command_executions":["cmd.exe /c whoami"]}}', "json")

        for kind, value in HASHES.items():
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                http = OfflineHTTP()
                client = LookupClient(store=EvidenceStore(directory), http=http,
                                      browser=UnavailableBrowser(),
                                      api_keys={"virustotal": "synthetic-key"}, interval=0)
                query = IOC(" " + value.upper() + " ", kind, ["original report"], "cti report")
                first = client.lookup_detailed(query, f"virustotal.{kind}_to_command_api")
                second = client.lookup_detailed(IOC(value, kind), f"virustotal.{kind}_to_command_api")
                self.assertEqual(len(http.requests), 1)
                self.assertFalse(first.cache_hit)
                self.assertTrue(second.cache_hit)
                self.assertNotEqual(first.id, second.id)
                self.assertEqual(first.input_ioc.value, value)
                self.assertEqual(first.outputs, second.outputs)
                self.assertEqual(query.value, " " + value.upper() + " ")
                self.assertEqual(query.context, ["original report"])

    def test_cache_separates_hash_queries_and_api_access(self):
        class OfflineHTTP:
            offline = True

            def __init__(self):
                self.requests = []

            def fetch(self, request):
                self.requests.append(request)
                return Document(request.url, '{"data":{"calls_highlighted":["GetTickCount"]}}', "json")

        with tempfile.TemporaryDirectory() as directory:
            store, http = EvidenceStore(directory), OfflineHTTP()
            first = LookupClient(store=store, http=http, browser=UnavailableBrowser(),
                                 api_keys={"virustotal": "first-key"}, interval=0)
            first.lookup(IOC(HASHES["sha256"], "sha256"), "virustotal.sha256_to_command_api")
            first.lookup(IOC("d" * 64, "sha256"), "virustotal.sha256_to_command_api")
            other_access = LookupClient(store=store, http=http, browser=UnavailableBrowser(),
                                        api_keys={"virustotal": "second-key"}, interval=0)
            receipt = other_access.lookup_detailed(IOC(HASHES["sha256"], "sha256"),
                                                   "virustotal.sha256_to_command_api")
            self.assertEqual(len(http.requests), 3)
            self.assertFalse(receipt.cache_hit)
            self.assertNotIn("second-key", json.dumps(receipt.to_dict()))

    def test_schema_failure_is_saved_and_does_not_poison_cache_as_empty(self):
        class OfflineHTTP:
            offline = True

            def __init__(self):
                self.requests = []

            def fetch(self, request):
                self.requests.append(request)
                body = ('{"data":{"command_executions":"still loading"}}' if len(self.requests) == 1
                        else '{"data":{"command_executions":["cmd.exe /c whoami"]}}')
                return Document(request.url, body, "json")

        with tempfile.TemporaryDirectory() as directory:
            store, http = EvidenceStore(directory), OfflineHTTP()
            client = LookupClient(store=store, http=http, browser=UnavailableBrowser(),
                                  api_keys={"virustotal": "synthetic-key"}, interval=0)
            query, method_id = IOC(HASHES["sha256"], "sha256"), "virustotal.sha256_to_command_api"
            with self.assertRaises(LookupError) as failure:
                client.lookup(query, method_id)
            failed = store.get_record(failure.exception.lookup_id)
            self.assertEqual(failed["status"], "parse_error")
            self.assertTrue(failed["responses"])
            with store.connect() as database:
                self.assertEqual(database.execute("SELECT COUNT(*) FROM cache").fetchone()[0], 0)
            recovered = client.lookup_detailed(query, method_id)
            self.assertEqual(recovered.status, "ok")
            self.assertFalse(recovered.cache_hit)
            self.assertEqual(len(http.requests), 2)

    def test_api_backup_uses_get_without_metadata_requests(self):
        class Response(BytesIO):
            status = 200

            def __init__(self, url):
                from email.message import Message
                super().__init__(b'{"data":{"calls_highlighted":["GetTickCount"]}}')
                self.url = url
                self.headers = Message()
                self.headers["Content-Type"] = "application/json"

        class Opener:
            def __init__(self):
                self.requests = []

            def open(self, request, timeout):
                self.requests.append(request)
                return Response(request.full_url)

        for kind, value in HASHES.items():
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                opener = Opener()
                with patch("ioc_hunter.transport.http.build_opener", return_value=opener):
                    client = LookupClient(store=EvidenceStore(directory), http=HTTPTransport(),
                                          browser=UnavailableBrowser(),
                                          api_keys={"virustotal": "synthetic-key"}, interval=0)
                    outputs = client.lookup(IOC(value, kind), f"virustotal.{kind}_to_command_api")
                self.assertEqual(len(opener.requests), 1)
                request = opener.requests[0]
                self.assertEqual(request.get_method(), "GET")
                self.assertEqual(request.full_url,
                                 f"https://www.virustotal.com/api/v3/files/{value}/behaviour_summary")
                self.assertEqual([ioc.value for ioc in outputs], ["GetTickCount"])

    def test_api_access_and_not_found_errors_remain_errors_not_empty_results(self):
        class Opener:
            def __init__(self, status):
                self.status, self.requests = status, []

            def open(self, request, timeout):
                self.requests.append(request)
                raise HTTPError(request.full_url, self.status, "synthetic provider error", {}, BytesIO())

        for status, expected in ((401, "login_required"), (403, "access_denied"),
                                 (404, "not_found"), (429, "rate_limited")):
            with self.subTest(status=status), tempfile.TemporaryDirectory() as directory:
                opener, store = Opener(status), EvidenceStore(directory)
                with patch("ioc_hunter.transport.http.build_opener", return_value=opener):
                    client = LookupClient(store=store, http=HTTPTransport(), browser=UnavailableBrowser(),
                                          api_keys={"virustotal": "synthetic-key"},
                                          interval=0)
                    with self.assertRaises(LookupError) as failure:
                        client.lookup(IOC(HASHES["sha256"], "sha256"), "virustotal.sha256_to_command_api")
                self.assertEqual(failure.exception.status, expected)
                self.assertEqual(len(opener.requests), 1)
                receipt = store.get_record(failure.exception.lookup_id)
                self.assertEqual(receipt["status"], expected)
                self.assertFalse(receipt["outputs"])
                with store.connect() as database:
                    self.assertEqual(database.execute("SELECT COUNT(*) FROM cache").fetchone()[0], 0)


if __name__ == "__main__":
    unittest.main()
