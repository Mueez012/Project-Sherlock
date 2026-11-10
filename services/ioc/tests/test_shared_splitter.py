"""IOC Hunter cuts reports with a byte-identical copy of the hub's splitter (ioc_hunter/text.py)."""

import hashlib
import unittest
from pathlib import Path

from ioc_hunter.extraction.pipeline import canonical_value, extract_report
from ioc_hunter.text import PUNKT_DIR, segment

HERE = Path(__file__).resolve().parent.parent  # services/ioc
HUB = HERE.parent.parent / "src" / "threatmamba"  # present in the Project Sherlock repo, absent in a lone checkout
PUNKT = {
    "abbrev_types.txt": "92a3e070f43d9b4c5534758ca40ad7343b04e7e29bfe0c2eb658a39445a4f779",
    "collocations.tab": "8e2da1225e4dd2cc9dba261ee231ccb134859e21b46006e7f472c5ee269af0cf",
    "ortho_context.tab": "4bbcca25ed3d3f06c02402abf8419b9f033b8adc06e7b482eca4e45f81a5dc4c",
    "sent_starters.txt": "f3f8535483e1dba487241b764945168123bca3209a9645e59acd1225dc76edac",
}


class SharedSplitterTests(unittest.TestCase):
    def test_punkt_data_is_unchanged(self):
        self.assertEqual({f: hashlib.sha256((PUNKT_DIR / f).read_bytes()).hexdigest() for f in PUNKT}, PUNKT)

    @unittest.skipUnless((HUB / "text.py").is_file(), "the hub is not in this checkout")
    def test_identical_to_the_hub_splitter(self):
        self.assertEqual((HERE / "ioc_hunter" / "text.py").read_bytes(), (HUB / "text.py").read_bytes())
        for name in PUNKT:
            hub_file = HUB / "data" / "punkt_tab" / "english" / name
            self.assertEqual((PUNKT_DIR / name).read_bytes(), hub_file.read_bytes())

    def test_an_indicator_in_a_list_takes_the_sentence_before_it_as_context(self):
        report = "The loader contacted 192.0.2.10 over port 443.\nIndicators:\nevil[.]com\n"
        result = extract_report(report)
        contexts = {ioc.value: ioc.context for ioc in result.iocs}
        self.assertEqual(contexts["evil.com"], ["The loader contacted 192.0.2.10 over port 443."])
        self.assertEqual([u.kind for u in segment(report)], ["sentence", "fragment", "ioc_list"])
        self.assertEqual(result.sentences, ["The loader contacted 192.0.2.10 over port 443.", "Indicators:", "evil[.]com"])

    def test_a_url_at_the_end_of_a_sentence_loses_the_full_stop(self):
        self.assertEqual(canonical_value("url", "http://update-check.net/a.bin."), "http://update-check.net/a.bin")
        result = extract_report("The payload came from hxxp://update-check[.]net/a.bin.")
        self.assertIn("http://update-check.net/a.bin", {ioc.value for ioc in result.iocs})


if __name__ == "__main__":
    unittest.main()
