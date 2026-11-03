"""Real browser tests with intercepted provider pages: no external requests."""
from contextlib import contextmanager
import importlib.util
import json
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from ioc_hunter.transport import BrowserTransport, FetchRequest, LookupError

@unittest.skipUnless(importlib.util.find_spec("playwright"), "Optional browser dependency not installed")
class BrowserTests(unittest.TestCase):
    def factory(self, handler):
        from playwright.sync_api import sync_playwright
        @contextmanager
        def configured():
            with sync_playwright() as runtime:
                def launch(**options):
                    try:
                        browser = runtime.chromium.launch(**options)
                    except Exception as exc:
                        if "Executable doesn't exist" in str(exc):
                            self.skipTest("Chromium runtime not installed")
                        raise
                    original = browser.new_context
                    def context(**kwargs):
                        result = original(**kwargs)
                        result.route("**/*", handler)
                        return result
                    browser.new_context = context
                    return browser
                yield SimpleNamespace(chromium=SimpleNamespace(launch=launch))
        return configured
    def test_delayed_tab_and_exact_response_capture(self):
        endpoint = "/api/v1/indicators/domain/example.com/passive_dns"
        body = '<body>Loading...<script>setTimeout(() => {document.body.innerHTML="<button>Passive DNS</button>";document.querySelector("button").onclick=()=>fetch("' + endpoint + '");}, 80)</script></body>'
        result = {"passive_dns": [{"hostname": "example.com", "address": "192.0.2.10", "record_type": "A"}]}
        def handle(route):
            if route.request.url.endswith(endpoint):
                route.fulfill(status=200, content_type="application/json", body=json.dumps(result))
            else:
                route.fulfill(status=200, content_type="text/html", body=body)
        request = FetchRequest("alienvault", "https://otx.alienvault.com/indicator/domain/example.com", "dns", (endpoint,), page_labels=("Passive DNS",))
        with patch("playwright.sync_api.sync_playwright", self.factory(handle)):
            doc = BrowserTransport(timeout=3).fetch(request)
        self.assertEqual(doc.format, "json")
        self.assertEqual(json.loads(doc.body), result)
    def test_private_ui_proxy_path_is_captured(self):
        endpoint = "/api-proxy/ui/domains/example.com/resolutions"
        body = '<body><script>fetch("' + endpoint + '");</script></body>'
        def handle(route):
            if route.request.url.endswith(endpoint):
                route.fulfill(status=200, content_type="application/json", body='{"data": []}')
            else:
                route.fulfill(status=200, content_type="text/html", body=body)
        request = FetchRequest("virustotal", "https://www.virustotal.com/gui/domain/example.com/relations", "dns", (endpoint,))
        with patch("playwright.sync_api.sync_playwright", self.factory(handle)):
            doc = BrowserTransport(timeout=3).fetch(request)
        self.assertEqual(json.loads(doc.body), {"data": []})
    def test_access_denied_is_distinct_from_empty_results(self):
        endpoint = "/ui/domains/example.com/resolutions"
        body = '<body><script>fetch("' + endpoint + '");</script></body>'
        def handle(route):
            if route.request.url.endswith(endpoint):
                route.fulfill(status=403, content_type="application/json", body='{"error":"denied"}')
            else:
                route.fulfill(status=200, content_type="text/html", body=body)
        request = FetchRequest("virustotal", "https://www.virustotal.com/gui/domain/example.com/relations", "dns", (endpoint,))
        with patch("playwright.sync_api.sync_playwright", self.factory(handle)), self.assertRaises(LookupError) as ctx:
            BrowserTransport(timeout=3).fetch(request)
        self.assertEqual(ctx.exception.status, "access_denied")

if __name__ == "__main__":
    unittest.main()
