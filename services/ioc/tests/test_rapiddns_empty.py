"""Synthetic regressions for RapidDNS's observed server-rendered zero count."""
from dataclasses import replace
import tempfile
import unittest

from ioc_hunter import IOC, LookupClient, LookupError, get_method
from ioc_hunter.providers import parse_document
from ioc_hunter.storage import EvidenceStore
from ioc_hunter.transport import Document


QUERY = IOC("188.190.17.232", "ipv4")
METHOD = get_method("rapiddns.ipv4_to_domain")
URL = "https://rapiddns.io/sameip/188.190.17.232?page=1"


def page(*, query=QUERY.value, total="0", limited=True, loading="", scope="result"):
    """Small provider-shaped fixture, without copying the user's saved page."""
    counter = f'<div>Total: <span>{total}</span></div>' if total is not None else ""
    guest = ('<div class="alert">Limited Access: You are using RapidDNS as a guest. '
             '<a href="/auth/github/login">Login with GitHub</a></div>') if limited else ""
    return ('<nav><span class="loading-text">Loading...</span></nav>'
            f'<div id="{scope}"><div>{query}</div>{counter}{guest}{loading}'
            '<table id="table"><thead><tr><th>#</th><th>Domain</th><th>Address</th>'
            '<th>Type</th><th>Date</th></tr></thead><tbody></tbody></table></div>')


class OnlyHTTPDocument:
    def __init__(self, document):
        self.document = document
        self.calls = 0

    def fetch(self, request):
        self.calls += 1
        if self.calls != 1:
            raise AssertionError("A completed HTTP response must not need a browser fallback")
        return self.document


class NoBrowser:
    def fetch(self, request):
        raise AssertionError("Unexpected browser fallback")


class RapidDNSEmptyTests(unittest.TestCase):
    def document(self, **kwargs):
        return Document(URL, page(**kwargs), "html")

    def assert_unfinished(self, document):
        with self.assertRaises(LookupError) as caught:
            parse_document(QUERY, METHOD, document)
        self.assertEqual(caught.exception.status, "loading_page")

    def test_guest_zero_count_is_partial_empty_without_browser_fallback(self):
        transport = OnlyHTTPDocument(self.document())
        with tempfile.TemporaryDirectory() as directory:
            client = LookupClient(store=EvidenceStore(directory), http=transport, browser=NoBrowser(), interval=0)
            receipt = client.lookup_detailed(QUERY, METHOD.id)
            self.assertEqual(receipt.outputs, [])
            self.assertEqual(receipt.status, "partial")
            self.assertFalse(receipt.complete)
            self.assertEqual(receipt.outcome_reason, "no_matching_records")
            self.assertIn("provider_limited", receipt.partial_reasons)
            self.assertEqual(receipt.transport_errors, [])
            self.assertEqual(len(receipt.responses), 1)
            self.assertEqual(transport.calls, 1)

    def test_unlimited_zero_count_is_completed_empty(self):
        parsed = parse_document(QUERY, METHOD, self.document(limited=False))
        self.assertEqual(parsed.observations, [])
        self.assertTrue(parsed.complete)

    def test_wrong_query_in_result_or_url_cannot_prove_empty(self):
        self.assert_unfinished(self.document(query="192.0.2.10"))
        self.assert_unfinished(replace(self.document(), url=URL.replace(QUERY.value, "192.0.2.10")))

    def test_missing_counter_keeps_empty_table_unfinished(self):
        self.assert_unfinished(self.document(total=None))

    def test_nonzero_counter_keeps_empty_table_unfinished(self):
        for total in ("1", "20", "0.5"):
            with self.subTest(total=total):
                self.assert_unfinished(self.document(total=total))

    def test_result_loading_overrides_zero_count(self):
        for loading in ('<div class="loading"></div>', '<div aria-busy="true"></div>', '<div>Loading...</div>'):
            with self.subTest(loading=loading):
                self.assert_unfinished(self.document(loading=loading))

    def test_result_challenge_or_access_blocker_cannot_be_completed_empty(self):
        for marker in ("Verify you are human", "CAPTCHA", "Checking your browser", "Just a moment",
                       "Please enable JavaScript", "Sign in to continue", "Login required", "Access denied"):
            with self.subTest(marker=marker):
                self.assert_unfinished(self.document(loading=f"<div>{marker}</div>"))

    def test_zero_count_outside_result_scope_does_not_prove_empty(self):
        self.assert_unfinished(self.document(scope="other"))
        document = self.document(total=None)
        self.assert_unfinished(replace(document, body="<div>Total: <span>0</span></div>" + document.body))

    def test_later_page_does_not_prove_total_empty(self):
        self.assert_unfinished(replace(self.document(), url=URL.replace("page=1", "page=2")))


if __name__ == "__main__":
    unittest.main()
