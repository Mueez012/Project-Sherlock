"""Shared provider gates and frozen corpus evidence; all transports are fakes."""
from pathlib import Path
import importlib.util
import json
import time
from unittest.mock import patch

import pytest

from ioc_hunter import IOC, LookupClient, LookupError
from ioc_hunter.storage import EvidenceStore
from ioc_hunter.transport import Document


METHOD = "rapiddns.domain_to_ipv4"
QUERY = IOC("example.com", "domain", ["Report context"], "report")
BODY = (Path(__file__).parent / "fixtures" / "rapiddns.html").read_text(encoding="utf-8")


class Transport:
    offline = False

    def __init__(self, *results, scope="anonymous"):
        self.results, self.requests, self.scope = list(results), [], scope

    def cache_scope(self):
        return self.scope

    def fetch(self, request):
        self.requests.append(request)
        if not self.results:
            raise AssertionError("Unexpected acquisition")
        result = self.results.pop(0)
        if isinstance(result, BaseException):
            raise result
        return result


def document():
    return Document("https://rapiddns.io/subdomain/example.com?page=1", BODY, "html")


def client(tmp_path, transport, **kwargs):
    return LookupClient(store=EvidenceStore(tmp_path), http=transport, browser=transport,
                        interval=0, cache_ttl=kwargs.pop("cache_ttl", 0), **kwargs)


def test_profiles_and_budget_are_shared_with_a_new_client(tmp_path):
    transport = Transport(document())
    first = client(tmp_path, transport, provider_limits={"rapiddns": {"interval": 0, "daily_limit": 1}})
    assert first.lookup_wait(QUERY, METHOD) is None
    receipt = first.lookup_detailed(QUERY, METHOD)
    assert receipt.acquisition["external_fetch_attempts"] == 1
    second = client(tmp_path, Transport())
    blocked = second.lookup_wait(QUERY, METHOD)
    assert blocked["reason"] == "budget_exhausted"
    assert blocked["remaining"] == 0 and blocked["daily_limit"] == 1
    assert second.rate_status("alienvault")["remaining"] == 500
    with pytest.raises(LookupError) as error:
        second.lookup_detailed(QUERY, METHOD)
    deferred = second.store.get_record(error.value.lookup_id)
    assert deferred["status"] == "deferred"
    assert deferred["acquisition"]["fetch_attempts"] == 0
    assert deferred["acquisition"]["retry_at"] > time.time()
    assert not second.http.requests


def test_persisted_cooldown_defers_without_dispatch(tmp_path):
    first = client(tmp_path, Transport())
    first.limiter.cooldown("rapiddns", 120)
    second = client(tmp_path, Transport())
    assert second.lookup_wait(QUERY, METHOD)["reason"] == "cooldown"
    with pytest.raises(LookupError) as error:
        second.lookup_detailed(QUERY, METHOD)
    receipt = second.store.get_record(error.value.lookup_id)
    assert receipt["status"] == "deferred"
    assert receipt["acquisition"]["defer_reason"] == "rate_limited"
    assert receipt["acquisition"]["external_fetch_attempts"] == 0
    assert not second.http.requests


def test_remote_429_is_an_attempt_and_sets_shared_cooldown(tmp_path):
    transport = Transport(LookupError("rate_limited", "Provider quota", retry_after=90))
    first = client(tmp_path, transport)
    with pytest.raises(LookupError) as error:
        first.lookup_detailed(QUERY, METHOD)
    receipt = first.store.get_record(error.value.lookup_id)
    assert receipt["status"] == "rate_limited"
    assert receipt["acquisition"]["fetch_attempts"] == 1
    assert receipt["acquisition"]["external_fetch_attempts"] == 1
    assert receipt["acquisition"]["retry_at"] >= time.time() + 85
    assert client(tmp_path, Transport()).lookup_wait(QUERY, METHOD)["reason"] == "cooldown"


def test_short_pacing_wait_is_measured_separately(tmp_path):
    lookup = client(tmp_path, Transport(document()), provider_limits={"rapiddns": {"interval": 7}})
    with lookup.store.connect() as db:
        db.execute("INSERT INTO provider_pacing VALUES ('rapiddns',107,0)")
    with patch("ioc_hunter.transport.limits.time.time", return_value=100), \
            patch("ioc_hunter.transport.limits.time.monotonic", side_effect=[100, 107]), \
            patch("ioc_hunter.transport.limits.time.sleep") as sleep:
        assert lookup.lookup_wait(QUERY, METHOD) is None
        receipt = lookup.lookup_detailed(QUERY, METHOD)
    sleep.assert_called_once_with(7)
    assert receipt.acquisition["rate_wait_seconds"] == 7


def test_frozen_evidence_survives_expiry_and_retains_independent_receipts(tmp_path):
    first = client(tmp_path, Transport(document()), frozen_cache=True, cache_namespace="d2-build-1",
                   provider_limits={"rapiddns": {"interval": 0, "daily_limit": 1}})
    original = first.lookup_detailed(QUERY, METHOD)
    second = client(tmp_path, Transport(), frozen_cache=True, cache_namespace="d2-build-1")
    assert second.lookup_wait(QUERY, METHOD) is None
    query = IOC("EXAMPLE.COM", "domain", ["Another report"], "another")
    reused = second.lookup_detailed(query, METHOD)
    assert reused.id != original.id and reused.input_ioc.context == ["Another report"]
    assert reused.outputs == original.outputs and reused.evidence == original.evidence
    assert reused.cache_hit and reused.acquisition["fetch_attempts"] == 0
    assert reused.acquisition["frozen_lookup_id"] == original.id
    assert second.store.get_record(original.id) == original.to_dict()
    assert second.store.get_record(reused.id) == reused.to_dict()
    assert not second.http.requests


@pytest.mark.parametrize("change", ["namespace", "limits", "access", "query"])
def test_frozen_evidence_respects_build_limits_access_and_query(tmp_path, change):
    first = client(tmp_path, Transport(document()), frozen_cache=True, cache_namespace="build",
                   provider_limits={"rapiddns": {"interval": 0, "daily_limit": 1}})
    first.lookup_detailed(QUERY, METHOD)
    kwargs = {"frozen_cache": True, "cache_namespace": "other" if change == "namespace" else "build"}
    if change == "limits":
        kwargs["max_pages"] = 2
    second = client(tmp_path, Transport(scope="signed-in" if change == "access" else "anonymous"), **kwargs)
    query = IOC("other.example", "domain") if change == "query" else QUERY
    assert second.lookup_wait(query, METHOD)["reason"] == "budget_exhausted"
    assert not second.http.requests


def test_cached_read_can_complete_during_cooldown_without_spending_quota(tmp_path):
    lookup = client(tmp_path, Transport(document()), cache_ttl=86400)
    original = lookup.lookup_detailed(QUERY, METHOD)
    lookup.limiter.cooldown("rapiddns", 120)
    assert lookup.lookup_wait(QUERY, METHOD) is None
    cached = lookup.lookup_detailed(QUERY, METHOD)
    assert cached.cache_hit and cached.acquisition["fetch_attempts"] == 0
    assert cached.acquisition["cache_reads"] == 1
    assert original.acquisition["parsed_pages"] == cached.acquisition["parsed_pages"] == 1
    assert len(lookup.http.requests) == 1


def test_composed_lookup_reports_mixed_cache_and_live_acquisition(tmp_path):
    from ioc_hunter.providers.base import FollowUp
    from ioc_hunter.providers.common import ObservationBuilder
    from ioc_hunter.transport import FetchRequest

    root_url = "https://rapiddns.io/subdomain/example.com?page=1"
    child_url = "https://rapiddns.io/subdomain/example.com?stage=child"
    root_request = FetchRequest("rapiddns", root_url, "dns")
    child_request = FetchRequest("rapiddns", child_url, "dns")

    def page(url, ip):
        return Document(url, json.dumps({"ip": ip}), "json")

    def parse(query, method, response):
        builder = ObservationBuilder(query, method, response)
        ip = json.loads(response.body)["ip"]
        builder.emit("ipv4", ip, "$.ip", {"ip": ip}, "dns_record",
                     {"domain": "example.com", "ip": ip, "record_type": "A"})
        if response.url == root_url:
            builder.result.followups.append(FollowUp("child", (("http", child_request),)))
        return builder.result

    lookup = client(tmp_path, Transport(page(root_url, "192.0.2.10"), page(child_url, "192.0.2.20"),
                                         page(child_url, "192.0.2.21")), cache_ttl=86400)
    with patch("ioc_hunter.lookup.requests_for", return_value=[("http", root_request)]), \
            patch("ioc_hunter.lookup.parse_document", side_effect=parse):
        lookup.lookup_detailed(QUERY, METHOD)
        with lookup.store.connect() as db:
            db.execute("DELETE FROM cache WHERE key=?", (lookup.store.cache_key(child_request, "http"),))
        mixed = lookup.lookup_detailed(QUERY, METHOD)
    assert mixed.cache_hit
    assert mixed.acquisition["fetch_attempts"] == mixed.acquisition["external_fetch_attempts"] == 1
    assert mixed.acquisition["cache_reads"] == 1
    assert mixed.acquisition["followups_executed"] == 1 and mixed.acquisition["parsed_pages"] == 2
    assert [response["cached"] for response in mixed.responses] == [True, False]
    assert {ioc.value for ioc in mixed.outputs} == {"192.0.2.10", "192.0.2.21"}


def test_invalid_profiles_do_not_change_shared_configuration(tmp_path):
    lookup = client(tmp_path, Transport())
    with pytest.raises(ValueError):
        lookup.configure_limits({"rapiddns": {"interval": 0}, "alienvault": {"daily_limit": 0}})
    assert lookup.store.provider_limit("rapiddns") is None
    with pytest.raises(ValueError):
        lookup.configure_limits(frozen_cache=True)


def test_missing_retry_after_uses_shared_bounded_backoff(tmp_path):
    profile = {"rapiddns": {"interval": 0, "backoff_seconds": 2, "max_backoff_seconds": 4}}
    for expected in (2, 4, 4):
        lookup = client(tmp_path, Transport(LookupError("rate_limited", "Provider quota")),
                        provider_limits=profile)
        with lookup.store.connect() as db:
            db.execute("UPDATE provider_pacing SET next_at=0,cooldown_until=0")
        with pytest.raises(LookupError) as error:
            lookup.lookup_detailed(QUERY, METHOD)
        assert error.value.retry_after == expected


@pytest.mark.skipif(not importlib.util.find_spec("playwright"), reason="Optional browser dependency not installed")
def test_optional_widget_429_does_not_override_completed_required_response():
    from test_source_readiness import EventBrowser, EventPage, PageResponse
    from ioc_hunter.transport import FetchRequest

    root = "https://otx.alienvault.com"
    path = "/otxapi/indicators/domain/passive_dns/python.org"
    optional = PageResponse(root + "/otxapi/comments", {})
    optional.status, optional.headers = 429, {"Retry-After": "123"}
    required = PageResponse(root + path, {"passive_dns": []})
    page = EventPage(responses=(optional, required))
    request = FetchRequest("alienvault", root + "/indicator/domain/python.org", "dns", (path,))
    result = EventBrowser(page).fetch(request)
    assert result.format == "json" and required.reads == 1 and optional.reads == 0
    assert result.diagnostics["optional_rate_limits"] == [{"path": "/otxapi/comments", "status": 429}]


@pytest.mark.skipif(not importlib.util.find_spec("playwright"), reason="Optional browser dependency not installed")
def test_optional_widget_429_remains_conservative_if_required_read_never_finishes():
    from test_source_readiness import EventBrowser, EventPage, PageResponse
    from ioc_hunter.transport import FetchRequest

    root = "https://otx.alienvault.com"
    optional = PageResponse(root + "/otxapi/comments", {})
    optional.status, optional.headers = 429, {"Retry-After": "123"}
    page = EventPage(responses=(optional,))
    request = FetchRequest("alienvault", root + "/indicator/domain/python.org", "dns", ("/required",))
    with pytest.raises(LookupError) as error:
        EventBrowser(page, timeout=0).fetch(request)
    assert error.value.status == "rate_limited" and error.value.retry_after == 123
    assert error.value.document.diagnostics["optional_rate_limits"]


@pytest.mark.skipif(not importlib.util.find_spec("playwright"), reason="Optional browser dependency not installed")
def test_frozen_lookup_reuses_captured_browser_pagination_without_another_session(tmp_path):
    from test_browser_transport import BrowserTests
    from ioc_hunter.transport import BrowserTransport

    path = "/otxapi/indicators/domain/url_list/example.com"
    html = ('<div id="url_list"><button class="page-change increment" onclick="fetch(\''
            + path + '?page=2&limit=10\')">Next</button></div><script>fetch("' + path + '")</script>')
    seen = []

    def handle(route):
        url = route.request.url
        seen.append(url)
        if path in url:
            second = "page=2" in url
            body = {"url_list": [{"url": "https://example.com/" + ("second" if second else "first")}],
                    "has_next": not second}
            route.fulfill(status=200, content_type="application/json", body=json.dumps(body))
        else:
            route.fulfill(status=200, content_type="text/html", body=html)

    with patch("playwright.sync_api.sync_playwright", BrowserTests().factory(handle)):
        lookup = LookupClient(store=EvidenceStore(tmp_path), browser=BrowserTransport(timeout=3),
                              api_keys={}, interval=0, cache_ttl=0, max_pages=2,
                              frozen_cache=True, cache_namespace="paginated-build")
        original = lookup.lookup_detailed(QUERY, "alienvault.domain_to_url")
        lookup.limiter.cooldown("alienvault", 120)
        count = len(seen)
        assert lookup.lookup_wait(QUERY, "alienvault.domain_to_url") is None
        reused = lookup.lookup_detailed(QUERY, "alienvault.domain_to_url")
    assert original.complete and len(original.outputs) == 2 and original.acquisition["fetch_attempts"] == 2
    assert reused.outputs == original.outputs and reused.acquisition["fetch_attempts"] == 0
    assert reused.acquisition["frozen_lookup_id"] == original.id and len(seen) == count
