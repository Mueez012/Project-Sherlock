"""Compose existing DNS operations into source-backed IOC discovery.

These parsers return DNS observations, not a judgement that two addresses
communicated. Acquisition remains in LookupClient; provider parsers only return
bounded follow-up descriptions alongside their ordinary observations.
"""
from dataclasses import replace
from urllib.parse import unquote, urlsplit

from ..method_spec import MethodSpec
from ..models import IOC, identity, normalize
from ..transport.models import Document, LookupError, allowed_url
from .base import FollowUp
from .common import ObservationBuilder


OPERATION = "dns_discovery"


def _context(original: IOC, query: IOC, stage: str) -> dict:
    return {"stage": stage, "query_type": query.type, "query_value": query.value,
            "input_type": original.type, "input_value": original.value}


def discovery_requests(ioc: IOC, method: MethodSpec, api_key, request_factory):
    """Adapt input for a supported existing route, retaining its alternatives."""
    kind, value = identity(ioc)
    if kind == "url":
        try:
            host = normalize("domain", urlsplit(value).hostname or "")
        except ValueError as exc:
            raise LookupError("invalid_request", "DNS URL discovery requires a domain hostname") from exc
        query = IOC(host, "domain", list(ioc.context), ioc.source)
        stage = "url_host"
    elif kind in {"ipv4", "ipv6"}:
        query = IOC(value, kind, list(ioc.context), ioc.source)
        stage = "seed"
    else:
        raise LookupError("invalid_request", "DNS discovery requires an IP address or URL")
    stage_method = replace(method, input_type=query.type, operation="dns")
    context = _context(ioc, query, stage)
    return [(transport, replace(request, context=context, integration_version="4"))
            for transport, request in request_factory(query, stage_method, api_key)]


def _query_from_document(original: IOC, method: MethodSpec, document: Document):
    context = document.diagnostics.get("request_context")
    if not isinstance(context, dict):
        raise LookupError("invalid_response", "Missing DNS discovery query context")
    try:
        if identity(IOC(context["input_value"], context["input_type"])) != identity(original):
            raise ValueError("Different original input")
        query = IOC(normalize(context["query_type"], context["query_value"]), context["query_type"])
        stage = context["stage"]
        if stage not in {"seed", "expand", "url_host"}:
            raise ValueError("Invalid discovery stage")
        if stage == "seed" and (query.type not in {"ipv4", "ipv6"} or identity(query) != identity(original)):
            raise ValueError("Different reverse-DNS input")
        if stage == "expand" and (original.type not in {"ipv4", "ipv6"} or query.type != "domain"):
            raise ValueError("Invalid domain expansion")
        if stage == "url_host" and (original.type != "url" or query.type != "domain"
                                     or query.value != normalize("domain", urlsplit(original.value).hostname or "")):
            raise ValueError("Different URL hostname")
    except (KeyError, ValueError, TypeError) as exc:
        raise LookupError("invalid_response", "Invalid DNS discovery query context") from exc
    if not _matches_query(method.source, query, document):
        raise LookupError("invalid_response", "DNS discovery response belongs to another source query")
    return query, stage


def _matches_query(source: str, query: IOC, document: Document) -> bool:
    """Bind both captured website JSON and configured API fallback responses."""
    if not allowed_url(source, document.url):
        return False
    path = unquote(urlsplit(document.url).path).rstrip("/")
    candidates = []
    if source == "rapiddns":
        candidates.append(("/api/search/", ""))
        candidates.append(("/subdomain/" if query.type == "domain" else "/sameip/", ""))
    elif source == "alienvault":
        kind = {"ipv4": "IPv4", "ipv6": "IPv6"}.get(query.type, query.type)
        ui_kind = "ip" if query.type == "ipv6" else kind
        candidates.extend(((f"/otxapi/indicators/{kind}/passive_dns/", ""),
                           (f"/api/v1/indicators/{kind}/", "/passive_dns"),
                           (f"/indicator/{ui_kind}/", "")))
    for prefix, suffix in candidates:
        if not path.startswith(prefix) or (suffix and not path.endswith(suffix)):
            continue
        raw = path[len(prefix):len(path) - len(suffix) if suffix else None]
        try:
            if normalize(query.type, raw) == query.value:
                return True
        except ValueError:
            continue
    return False


class DNSDiscoveryBuilder(ObservationBuilder):
    """Reuse native DNS table/envelope parsing with discovery-specific outputs."""
    def __init__(self, original: IOC, method: MethodSpec, document: Document):
        query, stage = _query_from_document(original, method, document)
        # Existing HTML parsing recognizes the dns operation. The output builder
        # retains the actual selected method and original input in its evidence.
        super().__init__(query, replace(method, input_type=query.type, operation="dns"), document)
        self.original, self.original_method, self.stage = original, method, stage
        self.output = ObservationBuilder(original, method, document)
        self.result = self.output.result
        self._domains = set()

    def dns(self, row, locator, *, implicit_resolution_type=False):
        if not isinstance(row, dict):
            raise LookupError("parse_error", "DNS record must be an object")
        record = row.get("attributes", row)
        if not isinstance(record, dict):
            raise LookupError("parse_error", "Invalid DNS attributes")
        domain = record.get("host_name", record.get("hostname", record.get("subdomain", record.get("domain", ""))))
        address = record.get("ip_address", record.get("address", record.get("value", "")))
        rrtype = record.get("type", record.get("record_type", ""))
        if rrtype not in {"A", "AAAA"}:
            return
        kind = "ipv6" if rrtype == "AAAA" else "ipv4"
        try:
            domain, address = normalize("domain", domain), normalize(kind, address)
        except (ValueError, TypeError, AttributeError):
            return
        if self.stage == "seed":
            if (kind, address) != identity(self.ioc) or domain in self._domains:
                return
            self._domains.add(domain)
            query = IOC(domain, "domain", list(self.original.context), self.original.source)
            stage_method = replace(self.original_method, input_type="domain", operation="dns")
            self.result.followups.append(FollowUp(
                key=f"dns:{self.original_method.source}:{domain}", ioc=query, method=stage_method,
                context=_context(self.original, query, "expand")))
            return
        if self.stage == "url_host":
            output_kind, value = "domain", domain
        else:
            output_kind, value = kind, address
            if (output_kind, value) == identity(self.original):
                return
        facts = {"stage": self.stage, "query_type": self.ioc.type, "query_value": self.ioc.value,
                 "input_type": self.original.type, "input_value": self.original.value,
                 "domain": domain, "ip": address, "record_type": rrtype, "value": value}
        self.output.emit(output_kind, value, locator, row, "dns_discovery", facts,
                         record.get("date", record.get("last", record.get("timestamp", ""))))
