import contextlib
import csv
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from ioc_hunter import interactive_extraction as extraction


class ExtractionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.nlp = extraction.create_sentencizer()

    def test_defanged_iocs_keep_original_sentence_context(self):
        text = 'The payload contacted "hxxps://example[.]com/download". It then used 192.0.2.10.'
        sentences = extraction.split_sentences(text, self.nlp)
        self.assertEqual(len(sentences), 2)
        objects = extraction.build_iocs(sentences, extraction.find_sentence_iocs(sentences), "report-1")
        lookup = {(ioc.type, ioc.value): ioc for ioc in objects}
        self.assertEqual(lookup[("domain", "example.com")].context, [sentences[0]])
        self.assertEqual(lookup[("url", "https://example.com/download")].context, [sentences[0]])
        self.assertEqual(lookup[("ipv4", "192.0.2.10")].context, [sentences[1]])
        self.assertTrue(all(ioc.source == "report-1" for ioc in objects))

    def test_repeated_ioc_appends_context_without_duplicate_objects(self):
        sentences = ["The host was 192.0.2.10.", "Later, 192.0.2.10 was reused."]
        objects = extraction.build_iocs(sentences, extraction.find_sentence_iocs(sentences), "report-2")
        self.assertEqual(len(objects), 1)
        self.assertEqual(objects[0].context, sentences)

    def test_hashes_and_ipv6(self):
        values = {"md5": "a" * 32, "sha1": "b" * 40, "sha256": "c" * 64,
                  "ipv6": "2001:db8::1"}
        sentences = [f"Observed value: {value}" for value in values.values()]
        pairs = {pair for matches in extraction.find_sentence_iocs(sentences) for pair in matches}
        for kind, value in values.items():
            self.assertIn((kind, value), pairs)

    def test_no_iocs(self):
        sentences = ["The analyst reviewed the report."]
        self.assertEqual(extraction.build_iocs(sentences, extraction.find_sentence_iocs(sentences), "source"), [])

    def extract(self, report):
        body, _ = extraction.filter_report_sections(report)
        sentences = extraction.split_sentences(body, self.nlp)
        return extraction.build_iocs(sentences, extraction.find_sentence_iocs(sentences), "cti report")

    def test_reference_sections_excluded_before_extraction(self):
        for heading in ["References", "REFERENCES:", "## References", "9. References",
                        "**Sources:**", "Bibliography", "Further Reading", "Related Articles:"]:
            with self.subTest(heading=heading):
                text = f"Contacted 192.0.2.10.\n{heading}\nhttps://reference.example.com/report\n"
                objects = self.extract(text)
                self.assertEqual([(x.type, x.value) for x in objects], [("ipv4", "192.0.2.10")])
                self.assertEqual(objects[0].context, ["Contacted 192.0.2.10."])

    def test_repeated_citation_labels(self):
        text = ("Contacted 192.0.2.10.\nReferences Author A https://one.example.com\n"
                "References Author B https://two.example.com\n")
        objects = self.extract(text)
        self.assertEqual([x.value for x in objects], ["192.0.2.10"])

    def test_inline_reference_heading_and_related_content(self):
        for heading in ["References: https://one.example.com/report", "Related Content: A review of example.com"]:
            with self.subTest(heading=heading):
                self.assertEqual(self.extract(heading), [])

    def test_reference_words_in_narrative_do_not_hide_evidence(self):
        text = "References to 192.0.2.10 were found in the malware.\nThe source server is 192.0.2.11."
        self.assertEqual({x.value for x in self.extract(text)}, {"192.0.2.10", "192.0.2.11"})

    def test_ioc_appendix_after_references_is_retained(self):
        text = ("References\nhttps://reference.example.com/report\n"
                "Appendix A: Indicators of Compromise\n192.0.2.10\n" + "a" * 64)
        self.assertEqual({x.value for x in self.extract(text)}, {"192.0.2.10", "a" * 64})

    def test_markdown_body_after_reference_section_is_retained(self):
        text = "## References\nhttps://reference.example.com\n## Observed infrastructure\n192.0.2.10"
        self.assertEqual([x.value for x in self.extract(text)], ["192.0.2.10"])

    def test_same_domain_in_body_and_references_keeps_body_context(self):
        text = "The payload contacted example.com.\nReferences\nhttps://example.com/research"
        objects = self.extract(text)
        self.assertEqual(len(objects), 1)
        self.assertEqual(objects[0].value, "example.com")
        self.assertEqual(objects[0].context, ["The payload contacted example.com."])

    def test_standalone_indicator_lists_have_local_contexts(self):
        text = "Observed domains:\nfirst.example.com (12)\nsecond.example.com (9)\n\n" + "b" * 64
        objects = self.extract(text)
        lookup = {x.value: x.context for x in objects}
        self.assertEqual(lookup["first.example.com"], ["first.example.com (12)"])
        self.assertEqual(lookup["second.example.com"], ["second.example.com (9)"])
        self.assertEqual(lookup["b" * 64], ["b" * 64])

    def test_url_line_does_not_absorb_following_paragraph(self):
        text = "Download: https://example.com/payload\nThe payload installed itself."
        objects = self.extract(text)
        self.assertTrue(objects)
        self.assertTrue(all("installed itself" not in c for x in objects for c in x.context))

    def test_soft_wrapped_prose_keeps_sentence_context(self):
        text = "The payload contacted\n192.0.2.10 to fetch its configuration."
        self.assertEqual(self.extract(text)[0].context, [text])

    def test_software_versions_are_not_ip_indicators(self):
        for text in ["Flash Player ActiveX 28.0.0.137 and earlier versions.",
                     "The software version 1.2.3.4 was vulnerable.", "Affected build: 1.2.3.4."]:
            with self.subTest(text=text):
                self.assertEqual(self.extract(text), [])

    def test_real_ip_in_same_sentence_as_version_is_retained(self):
        text = "Version 1.2.3.4 contacted IP address 192.0.2.10."
        self.assertEqual([x.value for x in self.extract(text)], ["192.0.2.10"])

    def test_same_value_used_as_version_and_ip_is_retained(self):
        text = "Version 1.2.3.4 contacted IP address 1.2.3.4."
        self.assertEqual([x.value for x in self.extract(text)], ["1.2.3.4"])

    def test_unlabelled_and_defanged_ips_are_retained(self):
        for text in ["Observed 28.0.0.137.", "The host was 192[.]0[.]2[.]10."]:
            with self.subTest(text=text):
                self.assertEqual(len(self.extract(text)), 1)

    def test_interactive_reference_exclusion_and_override(self):
        row = {"index": "9", "cti_content": "References\nhttps://reference.example.com/report"}
        for override in [False, True]:
            output = io.StringIO()
            with patch("builtins.input", return_value=""), contextlib.redirect_stdout(output):
                extraction.review_report(row, 1, Path("report.csv"), self.nlp, include_references=override)
            if override:
                self.assertIn('"value": "reference.example.com"', output.getvalue())
            else:
                self.assertIn("Excluded reference/navigation section", output.getvalue())
                self.assertIn("0 unique indicators", output.getvalue())

    def test_csv_and_excel_read_same_report(self):
        from openpyxl import Workbook

        with tempfile.TemporaryDirectory() as directory:
            csv_path = Path(directory) / "reports.csv"
            xlsx_path = Path(directory) / "reports.xlsx"
            rows = [["index", "cti_content"], ["9", "First line\nSecond line, with a comma."]]
            with csv_path.open("w", encoding="utf-8-sig", newline="") as stream:
                csv.writer(stream).writerows(rows)
            workbook = Workbook()
            for row in rows:
                workbook.active.append(row)
            workbook.save(xlsx_path)
            workbook.close()
            self.assertEqual(extraction.load_reports(csv_path), extraction.load_reports(xlsx_path))

    def test_missing_cti_column_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "invalid.csv"
            path.write_text("index,wrong_column\n1,text\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "cti_content"):
                extraction.load_reports(path)

    def test_stopping_prevents_later_processing(self):
        row = {"index": "9", "cti_content": "Contact 192.0.2.10."}
        with patch("builtins.input", return_value="q"), patch.object(extraction, "split_sentences") as split:
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertFalse(extraction.review_report(row, 1, Path("reports.csv"), self.nlp))
            split.assert_not_called()

    def test_each_stage_waits_before_its_operation(self):
        row = {"index": "9", "cti_content": "Contact 192.0.2.10."}
        output = io.StringIO()
        expected_stages = ["STEP 1/4", "STEP 2/4", "STEP 3/4"]

        def respond(prompt):
            stage = expected_stages.pop(0)
            self.assertIn(stage, output.getvalue())
            next_number = int(stage[5]) + 1
            self.assertNotIn(f"STEP {next_number}/4", output.getvalue())
            return ""

        with patch("builtins.input", side_effect=respond), contextlib.redirect_stdout(output):
            self.assertTrue(extraction.review_report(row, 1, Path("reports.csv"), self.nlp))
        text = output.getvalue()
        self.assertIn(">>> IOC FOUND", text)
        self.assertIn('"context": [', text)
        self.assertIn('"source": "cti report"', text)
        self.assertIn("STEP 4/4", text)
        self.assertEqual(expected_stages, [])


if __name__ == "__main__":
    unittest.main()
