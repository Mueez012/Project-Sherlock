"""Browser report identity matching with intercepted pages; no provider access."""
import importlib.util
import json
import unittest
from unittest.mock import patch

from ioc_hunter.transport import BrowserTransport, FetchRequest
from ioc_hunter.transport.browser import response_matches
import test_browser_transport


MD5 = "a" * 32
SHA256 = "b" * 64
OTHER = "c" * 64
BASE = "https://www.virustotal.com"


def request():
    return FetchRequest(
        "virustotal", f"{BASE}/gui/file/{MD5}/behavior", "file_behavior",
        (f"/ui/files/{MD5}/behaviours", "/ui/files/{page_id}/behaviours"),
        page_identity_pattern=r"/gui/file/([0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64})(?:/behavior)?/?",
    )


def test_response_path_is_bound_to_exact_current_file_page():
    req = request()
    response = f"{BASE}/ui/files/{SHA256}/behaviours?limit=40"
    assert response_matches(req, response, f"{BASE}/gui/file/{SHA256}")
    assert response_matches(req, response, f"{BASE}/gui/file/{SHA256}/behavior")
    for page in ("", f"{BASE}/gui/file/{OTHER}", f"{BASE}/gui/domain/sysinternals.com",
                 f"https://www.python.org/gui/file/{SHA256}"):
        assert not response_matches(req, response, page)
    assert not response_matches(req, response + "&cursor=next", f"{BASE}/gui/file/{SHA256}")
    assert not response_matches(req, f"{BASE}/ui/files/{SHA256}/contacted_ips", f"{BASE}/gui/file/{SHA256}")
    assert not response_matches(req, f"{BASE}/ui/files/{OTHER}/behaviours", f"{BASE}/gui/file/{SHA256}")


@unittest.skipUnless(importlib.util.find_spec("playwright"), "Optional browser dependency not installed")
class HashBrowserTests(unittest.TestCase):
    factory = test_browser_transport.BrowserTests.factory

    def test_page_canonical_hash_is_reused_without_fetching_metadata(self):
        req = request()
        endpoint = f"/ui/files/{SHA256}/behaviours"
        unrelated = f"/ui/files/{OTHER}/behaviours"
        requests = []
        payload = {"data": [{"id": SHA256 + "_synthetic", "type": "file_behaviour",
                             "attributes": {"calls_highlighted": ["GetTickCount"]}}]}
        html = ('<body><script>history.replaceState(null,"","/gui/file/' + SHA256 + '");'
                'fetch("' + unrelated + '").then(()=>fetch("' + endpoint + '?limit=40"));'
                '</script></body>')

        def handle(route):
            requests.append(route.request.url)
            if "/ui/files/" in route.request.url:
                body = payload if endpoint in route.request.url else {"data": []}
                route.fulfill(status=200, content_type="application/json", body=json.dumps(body))
            else:
                route.fulfill(status=200, content_type="text/html", body=html)

        with patch("playwright.sync_api.sync_playwright", self.factory(handle)):
            document = BrowserTransport(timeout=3).fetch(req)
        self.assertEqual(json.loads(document.body), payload)
        self.assertEqual(document.url, BASE + endpoint + "?limit=40")
        self.assertEqual(document.diagnostics["request_url"], req.url)
        self.assertEqual(document.diagnostics["page_url"], f"{BASE}/gui/file/{SHA256}")
        self.assertEqual(len(requests), 3)  # Page plus two page-generated responses.
