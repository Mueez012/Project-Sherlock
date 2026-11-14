"""Ordinary OTX pulse discovery and typed extraction; no network execution."""
from dataclasses import replace
import re
from urllib.parse import parse_qs, urlencode, urljoin, urlsplit

from ..models import IOC, normalize
from ..transport.models import FetchRequest, LookupError, allowed_url
from .base import FollowUp
from .common import ObservationBuilder, read_json, finish_page

OPERATION = "pulse_search"
SCHEMES = frozenset({"http", "https", "ftp"})
NATIVE_TYPES = {"domain": "domain", "hostname": "domain", "email": "email", "ipv4": "ipv4"}


def search_text(ioc):
    value = normalize(ioc.type, ioc.value)
    if ioc.type == "protocol" and value not in SCHEMES:
        raise LookupError("unsupported_input", "This operation currently extracts explicit HTTP, HTTPS and FTP URL ports")
    return value


def requests_for(ioc, method, api_key=""):
    headers = {"X-OTX-API-KEY": api_key} if api_key else {}
    if method.operation == "pulse_indicators":
        pulse_id = ioc.value
        if ioc.type != "pulse" or not re.fullmatch(r"[0-9a-f]{24}", pulse_id):
            raise LookupError("invalid_request", "Invalid internal pulse reference")
        # 'pulse' is a private navigation argument, never a public IOC type.
        api = f"https://otx.alienvault.com/api/v1/pulses/{pulse_id}/indicators"
        context = {"stage": "indicators", "pulse_id": pulse_id}
        routes = [("browser", FetchRequest(
            "alienvault", f"https://otx.alienvault.com/pulse/{pulse_id}", "pulse_indicators",
            (f"/otxapi/pulses/{pulse_id}/indicators/",), response_method="GET",
            bootstrap_paths=("/otxapi/env",), context=context, integration_version="2"))]
        if api_key:
            routes.append(("http", FetchRequest("alienvault", api, "pulse_indicators", headers=headers,
                                                  context=context, integration_version="2")))
        return routes
    keyword = search_text(ioc)
    params = {"q": keyword, "include_inactive": "0", "sort": "-modified", "page": "1",
              "limit": "10", "indicatorsSearch": keyword}
    context = {"stage": "search", "search_text": keyword}
    routes = [("browser", FetchRequest(
        "alienvault", "https://otx.alienvault.com/browse/global/pulses?" + urlencode(params), OPERATION,
        ("/otxapi/pulses/",), response_query={"q": keyword}, response_method="GET",
        bootstrap_paths=("/otxapi/env",), context=context, integration_version="1"))]
    if api_key:
        query = urlencode({"q": keyword, "page": "1", "limit": "25"})
        routes.append(("http", FetchRequest("alienvault", "https://otx.alienvault.com/api/v1/search/pulses?" + query,
                                             OPERATION, headers=headers, context=context, integration_version="1")))
    return routes


def parse_document(ioc, method, document):
    builder = ObservationBuilder(ioc, method, document)
    keyword = search_text(ioc)
    context = document.diagnostics.get("request_context", {})
    if not isinstance(context, dict) or context.get("search_text") != keyword or not allowed_url("alienvault", document.url):
        raise LookupError("invalid_response", "Missing query-bound pulse acquisition context")
    if context.get("stage") == "search":
        return _search(builder, keyword)
    pulse_id = context.get("pulse_id", "")
    if context.get("stage") != "indicators" or not re.fullmatch(r"[0-9a-f]{24}", pulse_id):
        raise LookupError("invalid_response", "Invalid pulse acquisition stage")
    path = urlsplit(document.url).path.rstrip("/")
    if path not in {f"/otxapi/pulses/{pulse_id}/indicators", f"/api/v1/pulses/{pulse_id}/indicators"}:
        raise LookupError("invalid_response", "Pulse response belongs to another pulse")
    data = read_json(document)
    rows = data.get("results")
    _rows(builder, rows, pulse_id, keyword, "$.results")
    _pagination(builder, data, len(rows))
    return finish_page(builder)


def _search(builder, keyword):
    document = builder.document
    parts = urlsplit(document.url)
    if (parts.path.rstrip("/") not in {"/otxapi/pulses", "/api/v1/search/pulses"}
            or parse_qs(parts.query).get("q") != [keyword]):
        raise LookupError("invalid_response", "Pulse search belongs to another query")
    data = read_json(document)
    rows = data.get("results")
    if not isinstance(rows, list):
        raise LookupError("parse_error", "Missing pulse search results")
    for row in rows:
        if not isinstance(row, dict) or not re.fullmatch(r"[0-9a-f]{24}", str(row.get("id", ""))):
            raise LookupError("parse_error", "Invalid pulse search reference")
        pulse_id = row["id"]
        counts = row.get("indicator_type_counts")
        needed = {"domain": ("domain", "hostname"), "email": ("email",), "ipv4": ("IPv4",),
                  "port": ("URL",), "protocol": ("URL",)}[builder.method.output_type]
        if isinstance(counts, dict) and all(type(number) is int and number >= 0 for number in counts.values()):
            if not any(counts.get(kind, 0) for kind in needed):
                continue
        builder.result.followups.append(FollowUp(
            "otx-pulse:" + pulse_id, ioc=IOC(pulse_id, "pulse"),
            method=replace(builder.method, input_type="pulse", operation="pulse_indicators"),
            context={"stage": "indicators", "pulse_id": pulse_id, "search_text": keyword}))
    _pagination(builder, data, len(rows))
    return finish_page(builder)


def _pagination(builder, data, length):
    next_value = data.get("next")
    if isinstance(next_value, str) and next_value:
        builder.result.next_url = urljoin(builder.document.url, next_value)
    elif next_value:
        builder.result.complete = False
        builder.result.reason = "pulse_pagination_unverified"
    count = data.get("count")
    if isinstance(count, int) and count > length and not builder.result.next_url:
        builder.result.complete = False
        builder.result.reason = "pulse_results_capped"


def _rows(builder, rows, pulse_id, keyword, prefix):
    if not isinstance(rows, list):
        raise LookupError("parse_error", "Missing pulse indicator rows")
    for index, row in enumerate(rows):
        if not isinstance(row, dict) or not isinstance(row.get("type"), str) or not isinstance(row.get("indicator"), str):
            raise LookupError("parse_error", "Malformed pulse indicator")
        _indicator(builder, row, pulse_id, keyword, f"{prefix}[{index}].indicator")


def _indicator(builder, row, pulse_id, keyword, locator):
    indicator_type, indicator = row["type"], row["indicator"]
    facts = {"pulse_id": pulse_id, "search_text": keyword, "indicator_type": indicator_type,
             "indicator": indicator}
    kind = NATIVE_TYPES.get(indicator_type.lower())
    if kind:
        facts["value"] = indicator
        builder.emit(kind, indicator, locator, row, "otx_pulse_indicator", facts, row.get("created", ""))
        return
    if indicator_type.lower() != "url" or builder.method.output_type not in {"port", "protocol"}:
        return
    try:
        url = normalize("url", indicator)
        parts = urlsplit(url)
        if parts.scheme not in SCHEMES or parts.port is None:
            return
    except ValueError:
        return
    scheme, port = parts.scheme, str(parts.port)
    if builder.ioc.type == "port" and keyword == port:
        kind, value = "protocol", scheme
    elif builder.ioc.type == "protocol" and keyword == scheme:
        kind, value = "port", port
    else:
        return
    facts.update(url=url, scheme=scheme, explicit_port=port, value=value)
    builder.emit(kind, value, locator, row, "otx_pulse_indicator", facts, row.get("created", ""))


