"""Public compatibility and newly exposed extraction/discovery contracts."""
import contextlib
from dataclasses import asdict
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from ioc_hunter import IOC, extract_report, list_candidates, list_runnable_methods
from ioc_hunter import interactive_extraction as review
from ioc_hunter.extraction import create_sentencizer
from ioc_hunter.extraction.pipeline import split_sentences
from ioc_hunter.main import main
from ioc_hunter.methods import get_method, list_methods, method_status
from ioc_hunter.providers import PROVIDERS, parse_document
from ioc_hunter.storage import EvidenceStore
from ioc_hunter.transport import Document
from ioc_hunter.validation import validate_edge


class ExtractionInterfaceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.nlp = create_sentencizer()

    def test_extract_without_console_io_keeps_original_context(self):
        report = "The server uses 192.0.2.10.\n\nReferences\nhttps://publisher.example/article\n"
        output = io.StringIO()
        with patch("builtins.input", side_effect=AssertionError("Unexpected prompt")):
            with contextlib.redirect_stdout(output):
                result = extract_report(report, source="report-1", nlp=self.nlp)
        self.assertEqual(output.getvalue(), "")
        self.assertEqual(result.original_text, report)
        self.assertEqual(result.iocs, [IOC("192.0.2.10", "ipv4", ["The server uses 192.0.2.10."], "report-1")])
        self.assertEqual(result.excluded_sections[0]["heading"], "References")
        self.assertIs(review.split_sentences, split_sentences)
        self.assertIs(review.IOC, IOC)
        json.dumps(asdict(result))

    def test_reference_and_extended_options_remain_explicit(self):
        text = "Contact Analyst@example.com about CVE-2024-12345.\n\nReferences\n192.0.2.10\n"
        default = extract_report(text, nlp=self.nlp)
        extended = extract_report(text, nlp=self.nlp, include_references=True, extended_types=True)
        self.assertFalse(any(i.type in {"email", "cve", "ipv4"} for i in default.iocs))
        self.assertTrue({("email", "analyst@example.com"), ("cve", "CVE-2024-12345"), ("ipv4", "192.0.2.10")}
                        <= {(i.type, i.value) for i in extended.iocs})

    def test_empty_report_and_bad_input(self):
        self.assertEqual(extract_report("", nlp=self.nlp).iocs, [])
        with self.assertRaises(ValueError):
            extract_report(None, nlp=self.nlp)

    def test_extract_cli_emits_structured_result(self):
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "report.txt"
            report.write_text("The server uses 192.0.2.10.", encoding="utf-8")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                code = main(["extract", str(report)])
            self.assertEqual(code, 0)
            result = json.loads(output.getvalue())
            self.assertEqual(result["iocs"][0]["value"], "192.0.2.10")
            self.assertEqual(result["source"], str(report))


class RegistryCompatibilityTests(unittest.TestCase):
    def test_legacy_catalogue_and_provider_declarations_agree(self):
        self.assertEqual(len(list_methods()), 60)
        self.assertEqual(len(list_runnable_methods()), 21)
        self.assertEqual(len(list_candidates()), 39)
        declared = {m.id for provider in PROVIDERS.values() for m in provider.METHODS}
        self.assertEqual(declared, {m.id for m in list_runnable_methods()})
        self.assertFalse(declared & {m.id for m in list_candidates()})
        self.assertFalse(get_method("alienvault.ipv6_to_domain").baseline)
        self.assertTrue(get_method("rapiddns.ipv6_to_domain").baseline)

    def test_local_configuration_is_not_live_verification(self):
        method = get_method("virustotal.domain_to_ipv4")
        status = method_status(method, api_keys={"virustotal": "secret-test-value"})
        self.assertTrue(status["api_key_configured"])
        self.assertEqual(status["live_access"], "not_checked")
        self.assertNotIn("secret-test-value", json.dumps(status))
        self.assertEqual(method_status(get_method("rapiddns.domain_to_url"))["implementation"], "candidate")

    def test_cli_old_and_new_discovery_filters(self):
        for args, count in (([], 60), (["--implemented"], 21), (["--candidates"], 39)):
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(main(["methods", *args]), 0)
            self.assertEqual(len(json.loads(output.getvalue())), count)

    def test_original_imports_resolve_to_new_implementations(self):
        from ioc_hunter.methods import MethodSpec
        from ioc_hunter.method_spec import MethodSpec as SharedMethodSpec
        from ioc_hunter.transport import BrowserTransport, HTTPTransport
        from ioc_hunter.transport.browser import BrowserTransport as Browser
        from ioc_hunter.transport.http import HTTPTransport as HTTP
        from ioc_hunter.__main__ import main as legacy_main
        self.assertIs(MethodSpec, SharedMethodSpec)
        self.assertIs(BrowserTransport, Browser)
        self.assertIs(HTTPTransport, HTTP)
        self.assertIs(legacy_main, main)


class DiagnosticCompatibilityTests(unittest.TestCase):
    def test_domain_mismatch_explains_the_rejected_relationship(self):
        fixture = Path(__file__).parent / "fixtures" / "rapiddns.html"
        document = Document("https://rapiddns.io/subdomain/example.com", fixture.read_text(), "html")
        query, method = IOC("example.com", "domain"), get_method("rapiddns.domain_to_ipv4")
        observations = parse_document(query, method, document).observations
        rejected = next(obs for obs in observations if obs.evidence.facts["domain"] == "sub.example.com")
        result = validate_edge(query, rejected.ioc, method, rejected.evidence)
        self.assertFalse(result.accepted)
        self.assertEqual(result.reason, "dns_domain_mismatch")
        self.assertEqual(result.details, {"expected_domain": "example.com", "observed_domain": "sub.example.com"})
        self.assertIn("sub.example.com", result.message)
        self.assertEqual(result.evidence_id, rejected.evidence.id)

    def test_old_receipts_remain_readable_without_rewriting(self):
        old_record = {"id": "old-receipt", "status": "ok", "rejected": [
            {"type": "ipv4", "value": "192.0.2.11", "reason": "relationship_not_supported_by_fields",
             "evidence_id": "old-evidence"}]}
        with tempfile.TemporaryDirectory() as directory:
            store = EvidenceStore(directory)
            with store.connect() as db:
                db.execute("INSERT INTO lookups VALUES (?, ?, ?, ?)",
                           ("old-receipt", "old-key", json.dumps(old_record), 0))
            self.assertEqual(store.get_record("old-receipt"), old_record)


if __name__ == "__main__":
    unittest.main()
