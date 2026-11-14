"""Browser-event and local DOM regressions; no provider network access.

The page doubles emit response/requestfinished events through the production
BrowserTransport listeners. All payloads are invented transport examples, not
claims about the Hybrid Analysis search API's current request schema.
"""
from contextlib import contextmanager
from dataclasses import replace
import importlib.util
import json
from types import SimpleNamespace

import pytest

from ioc_hunter.transport import BrowserTransport, FetchRequest, LookupError
from ioc_hunter.transport.browser import html_ready, response_matches


BASE = "https://hybrid-analysis.com"
QUERY = 'filename:"payload.exe"'
SEARCH_URL = BASE + "/bff/proxy/search"
SHA256 = "a" * 64


@pytest.mark.skipif(not importlib.util.find_spec("playwright"), reason="Optional browser dependency not installed")
def test_script_readiness_uses_text_content_in_a_real_local_browser_dom():
    from playwright.sync_api import sync_playwright
    request = FetchRequest("hybridanalysis", BASE + "/sample/" + SHA256, "ha_report",
                           capture_html=True, ready_selector="script", ready_text="initialData")
    with sync_playwright() as runtime:
        browser = runtime.chromium.launch(headless=True)
        try:
            page = browser.new_page()
            page.route("**/*", lambda route: route.abort())
            page.set_content('<script type="application/json">{"initialData":{}}</script>')
            # Playwright's text engine excludes script elements, which caused
            # actual report pages to time out despite passing page-double tests.
            assert page.locator("script:has-text('initialData')").count() == 0
            assert html_ready(page, request)
            assert not html_ready(page, replace(request, ready_text="anotherReport"))
            page.set_content('<main>initialData</main><script type="application/json">{}</script>')
            assert not html_ready(page, request)
        finally:
            browser.close()


def bound_search_request():
    return FetchRequest(
        "hybridanalysis", BASE + "/search", "ha_report", ("/bff/proxy/search",),
        response_query={"q": QUERY}, response_method="POST",
        response_body={"query": QUERY, "options.window": "all"})


def response_url(**extra):
    from urllib.parse import urlencode
    return SEARCH_URL + "?" + urlencode({"q": QUERY, **extra})


def bound_body(**changes):
    return json.dumps({"query": QUERY, "options": {"window": "all"}, **changes})


def test_exact_query_method_and_nested_body_are_bound_independently():
    request = bound_search_request()
    assert response_matches(request, response_url(), post_data=bound_body(), method="POST")
    assert response_matches(request, response_url(), post_data=bound_body(), method="post")
    assert not response_matches(request, response_url(), post_data=bound_body(), method="GET")
    assert not response_matches(request, response_url(), post_data=bound_body())
    assert not response_matches(request, response_url(),
                                post_data=bound_body(query='filename:"different.exe"'), method="POST")
    assert not response_matches(request, response_url(),
                                post_data=bound_body(options={"window": "hour"}), method="POST")


@pytest.mark.parametrize("body", [None, "", "not-json", "[]", "{}", "null",
                                    '{"query":"other"}', '{"query":12,"options":[]}'])
def test_missing_or_malformed_body_cannot_match_the_same_provider_path(body):
    assert not response_matches(bound_search_request(), response_url(), post_data=body, method="POST")


def test_query_binding_rejects_another_query_duplicate_values_and_prefetched_pages():
    request = bound_search_request()
    body = bound_body()
    for url in (SEARCH_URL, response_url(q='filename:"other.exe"'), response_url() + "&q=other",
                response_url(page=2), response_url(cursor="prefetched"),
                "https://www.python.org/bff/proxy/search", BASE + "/bff/proxy/search/facets"):
        assert not response_matches(request, url, post_data=body, method="POST")


def test_continuation_must_match_its_exact_cursor_and_still_match_original_query_and_body():
    next_url = response_url(cursor="verified-next")
    request = replace(bound_search_request(), continuation_url=next_url)
    assert response_matches(request, next_url, post_data=bound_body(), method="POST")
    assert not response_matches(request, response_url(cursor="other"), post_data=bound_body(), method="POST")
    assert not response_matches(request, next_url,
                                post_data=bound_body(query='filename:"other.exe"'), method="POST")
    assert not response_matches(request, response_url(q="other", cursor="verified-next"),
                                post_data=bound_body(), method="POST")


def test_legacy_json_capture_keeps_existing_defaults_and_page_rejection():
    request = FetchRequest(
        "alienvault", "https://otx.alienvault.com/indicator/domain/python.org", "dns",
        ("/otxapi/indicators/domain/passive_dns/python.org",))
    endpoint = "https://otx.alienvault.com/otxapi/indicators/domain/passive_dns/python.org"
    assert response_matches(request, endpoint)
    assert response_matches(request, endpoint + "?page=1")
    # Optional request-body/method constraints do not retroactively constrain
    # existing providers that have never declared them.
    assert response_matches(request, endpoint, post_data="not-json", method="POST")
    assert not response_matches(request, endpoint + "?page=2")
    assert not response_matches(request, endpoint + "?cursor=prefetched")
    assert not response_matches(request, endpoint.replace("python.org", "github.com"))


def test_legacy_typed_ipv6_path_canonicalization_survives_new_binding_fields():
    request = FetchRequest(
        "alienvault", "https://otx.alienvault.com/indicator/ip/2001:db8::1", "dns",
        ("/otxapi/indicators/IPv6/passive_dns/2001%3Adb8%3A%3A1",), identity_type="ipv6")
    assert response_matches(
        request, "https://otx.alienvault.com/otxapi/indicators/IPv6/passive_dns/2001:0db8::1")
    assert not response_matches(
        request, "https://otx.alienvault.com/otxapi/indicators/IPv6/passive_dns/2001:db8::2")


def test_html_capture_requires_an_explicit_readiness_selector_before_browser_startup():
    request = FetchRequest("hybridanalysis", BASE + "/sample/" + SHA256, "ha_report", capture_html=True)
    with pytest.raises(LookupError) as failure:
        BrowserTransport().fetch(request)
    assert failure.value.status == "invalid_request"


class PageRequest:
    def __init__(self, url, *, method="GET", post_data=None):
        self.url, self.method, self.post_data = url, method, post_data
        self.resource_type = "fetch"
        self.finished = False
        self.failure = None


class PageResponse:
    def __init__(self, url, payload, *, method="GET", post_data=None):
        self.url, self.payload = url, payload
        self.request = PageRequest(url, method=method, post_data=post_data)
        self.status = 200
        self.headers = {"content-type": "application/json"}
        self.reads = 0

    def text(self):
        assert self.request.finished, "A response body was read before requestfinished"
        self.reads += 1
        return json.dumps(self.payload)


class AttachedMarker:
    def __init__(self, text=""):
        self.text = text

    def count(self):
        return 1

    def evaluate_all(self, expression, text):
        return text in self.text

    def is_visible(self):
        raise AssertionError("Attached script readiness must not require visual visibility")


class EventPage:
    def __init__(self, *, marker="", html="", responses=(), final_url=""):
        self.marker, self.html = marker, html
        self.responses, self.final_url = responses, final_url
        self.url = "about:blank"
        self.listeners = {}
        self.content_reads = 0
        self.waits = 0

    def set_default_timeout(self, timeout):
        assert timeout > 0

    def on(self, event, listener):
        self.listeners[event] = listener

    def remove_listener(self, event, listener):
        assert self.listeners.pop(event) is listener

    def goto(self, url, **options):
        self.url = self.final_url or url
        for response in self.responses:
            self.listeners["response"](response)
            response.request.finished = True
            self.listeners["requestfinished"](response.request)
        return SimpleNamespace(status=200, headers={"content-type": "text/html"})

    def locator(self, selector):
        assert selector == self.marker, "Unexpected selector or legacy table-readiness fallback"
        return AttachedMarker(self.html)

    def content(self):
        self.content_reads += 1
        return self.html

    def wait_for_timeout(self, timeout):
        self.waits += 1
        raise AssertionError("Ready source data should return before any polling wait")


class EventBrowser(BrowserTransport):
    def __init__(self, page, **options):
        super().__init__(**options)
        self.page = page

    @contextmanager
    def _page(self, request):
        yield self.page


@pytest.mark.skipif(not importlib.util.find_spec("playwright"), reason="Optional browser dependency not installed")
class TestSourceBrowserEvents:
    @pytest.mark.parametrize("status,expected", [(401, "login_required"), (403, "access_denied")])
    def test_denied_search_bootstrap_is_not_a_successful_html_empty(self, status, expected):
        selector = "section.results"
        response = PageResponse(BASE + "/bff/proxy/search", {"error": "restricted"}, method="POST")
        response.status = status
        page = EventPage(marker=selector, html="<section class='results'>No results found</section>",
                         responses=(response,))
        request = FetchRequest("hybridanalysis", BASE + "/search?q=filename:test.bin", "ha_report",
                               capture_html=True, ready_selector=selector,
                               bootstrap_paths=("/bff/proxy/search",))
        with pytest.raises(LookupError) as failure:
            EventBrowser(page).fetch(request)
        assert failure.value.status == expected
        assert failure.value.document.status_code == 200
        assert failure.value.document.diagnostics["terminal_state"] == expected
        assert response.reads == 0

    def test_local_network_denial_is_distinguished_from_a_provider_failure(self):
        from playwright.sync_api import Error as BrowserError
        page = EventPage()

        def denied(*args, **kwargs):
            raise BrowserError("Page.goto: net::ERR_NETWORK_ACCESS_DENIED at https://hybrid-analysis.com/?token=private")

        page.goto = denied
        request = FetchRequest("hybridanalysis", BASE + "/sample/" + SHA256, "ha_report",
                               capture_html=True, ready_selector="script:has-text('initialData')")
        with pytest.raises(LookupError) as failure:
            EventBrowser(page).fetch(request)
        assert failure.value.status == "network_access_denied"
        assert "private" not in str(failure.value)

    def test_attached_initial_data_script_returns_html_in_the_first_readiness_iteration(self):
        selector = "script"
        html = '<body><script type="application/json">{"initialData":{"sha256":"' + SHA256 + '"}}</script></body>'
        page = EventPage(marker=selector, html=html)
        request = FetchRequest("hybridanalysis", BASE + "/sample/" + SHA256, "ha_report",
                               capture_html=True, ready_selector=selector, ready_text="initialData")
        document = EventBrowser(page, timeout=60).fetch(request)
        assert document.body == html and document.format == "html"
        assert document.diagnostics["terminal_state"] == "html_ready"
        assert document.diagnostics["request_url"] == document.url == request.url
        assert page.waits == 0 and page.content_reads == 1 and not page.listeners

    def test_wrong_method_query_or_post_body_responses_do_not_replace_bound_search_response(self):
        wrong_method = PageResponse(response_url(), {"wrong": "method"}, method="GET", post_data=bound_body())
        wrong_query = PageResponse(response_url(q="other"), {"wrong": "query"},
                                   method="POST", post_data=bound_body())
        wrong_body = PageResponse(response_url(), {"wrong": "body"}, method="POST",
                                  post_data=bound_body(query="other"))
        prefetched = PageResponse(response_url(page=2), {"wrong": "page"}, method="POST", post_data=bound_body())
        expected = PageResponse(response_url(), {"data": [{"sha256": SHA256}]},
                                method="POST", post_data=bound_body())
        page = EventPage(responses=(wrong_method, wrong_query, wrong_body, prefetched, expected))
        document = EventBrowser(page).fetch(bound_search_request())
        assert json.loads(document.body) == expected.payload
        assert document.diagnostics["terminal_state"] == "response_complete"
        assert expected.reads == 1
        assert [response.reads for response in (wrong_method, wrong_query, wrong_body, prefetched)] == [0, 0, 0, 0]
        assert page.waits == page.content_reads == 0 and not page.listeners

    def test_existing_json_operation_still_returns_completed_response_without_html_capture(self):
        endpoint = "https://otx.alienvault.com/otxapi/indicators/domain/passive_dns/python.org"
        response = PageResponse(endpoint, {"passive_dns": []})
        page = EventPage(responses=(response,))
        request = FetchRequest("alienvault", "https://otx.alienvault.com/indicator/domain/python.org", "dns",
                               ("/otxapi/indicators/domain/passive_dns/python.org",))
        document = EventBrowser(page).fetch(request)
        assert document.format == "json" and json.loads(document.body) == {"passive_dns": []}
        assert response.reads == 1 and document.diagnostics["terminal_state"] == "response_complete"
        assert page.waits == page.content_reads == 0 and not page.listeners

    def test_html_readiness_cannot_capture_a_page_outside_the_provider(self):
        selector = "script:has-text('initialData')"
        page = EventPage(marker=selector, html="untrusted", final_url="https://www.python.org/")
        request = FetchRequest("hybridanalysis", BASE + "/sample/" + SHA256, "ha_report",
                               capture_html=True, ready_selector=selector)
        with pytest.raises(LookupError) as failure:
            EventBrowser(page).fetch(request)
        assert failure.value.status == "unsafe_redirect"
        assert page.content_reads == page.waits == 0 and not page.listeners

    def test_html_readiness_keeps_existing_response_size_limit(self):
        selector = "script:has-text('initialData')"
        page = EventPage(marker=selector, html="x" * 21)
        request = FetchRequest("hybridanalysis", BASE + "/sample/" + SHA256, "ha_report",
                               capture_html=True, ready_selector=selector)
        with pytest.raises(LookupError) as failure:
            EventBrowser(page, max_bytes=20).fetch(request)
        assert failure.value.status == "response_too_large"
        assert page.waits == 0 and not page.listeners
