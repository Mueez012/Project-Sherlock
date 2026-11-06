"""Shared field-to-evidence conversion and bounded page parsing.

Provider-specific endpoints and JSON containers belong in each source module.
"""
from html.parser import HTMLParser
import json
from urllib.parse import urlsplit, urljoin, urlencode, parse_qs, urlunsplit
from ..evidence import Observation, make_evidence
from ..models import IOC, normalize
from ..transport.models import LookupError, allowed_url
from .base import ParsedPage

class ResultTables(HTMLParser):
    """Read result tables and navigation, excluding scripts/style from cell text."""
    def __init__(self, section_id=None):
        super().__init__(convert_charrefs=True)
        self.tables, self.links, self.text = [], [], []
        self.table = None
        self.row = None
        self.cell = None
        self.anchor = None
        self.hidden = 0
        self.section_id, self.scope_depth, self.busy = section_id, 0, False
    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if self.section_id:
            if tag == "div" and (self.scope_depth or attrs.get("id") == self.section_id):
                self.scope_depth += 1
            if not self.scope_depth:
                return
        if "loading" in attrs.get("class", "").split() or attrs.get("aria-busy") == "true":
            self.busy = True
        if tag in {"script", "style"}:
            self.hidden += 1
        if tag == "table":
            self.table = []
        elif tag == "tr" and self.table is not None:
            self.row = []
        elif tag in {"td", "th"} and self.row is not None:
            self.cell = []
        elif tag == "a":
            self.anchor = [attrs.get("href", ""), [], attrs.get("rel", "")]
    def handle_data(self, data):
        if self.hidden or (self.section_id and not self.scope_depth):
            return
        self.text.append(data)
        if self.cell is not None:
            self.cell.append(data)
        if self.anchor is not None:
            self.anchor[1].append(data)
    def handle_endtag(self, tag):
        if self.section_id:
            if not self.scope_depth:
                return
            if tag == "div":
                self.scope_depth -= 1
        if tag in {"script", "style"}:
            self.hidden = max(0, self.hidden - 1)
        elif tag in {"td", "th"} and self.cell is not None:
            self.row.append(" ".join("".join(self.cell).split()))
            self.cell = None
        elif tag == "tr" and self.row is not None:
            self.table.append(self.row)
            self.row = None
        elif tag == "table" and self.table is not None:
            self.tables.append(self.table)
            self.table = None
        elif tag == "a" and self.anchor is not None:
            self.links.append((self.anchor[0], "".join(self.anchor[1]).strip(), self.anchor[2]))
            self.anchor = None

def _next_page(url, page):
    parts = urlsplit(url)
    query = parse_qs(parts.query)
    query["page"] = [str(page)]
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query, doseq=True), ""))

class ObservationBuilder:
    def __init__(self, ioc, method, document):
        self.ioc, self.method, self.document = ioc, method, document
        self.result = ParsedPage()

    def emit(self, kind, value, locator, record, fact_type, facts, observed=""):
        if kind != self.method.output_type:
            return
        try:
            value = normalize(kind, value)
        except (ValueError, TypeError, AttributeError):
            return
        evidence = make_evidence(self.method.source, self.ioc, self.method.operation, self.document, locator,
                                 record, fact_type, facts, str(observed or ""))
        self.result.observations.append(Observation(IOC(value, kind, [evidence.excerpt], self.method.source), evidence))
    def dns(self, row, locator, *, implicit_resolution_type=False):
        if not isinstance(row, dict):
            raise LookupError("parse_error", "DNS record must be an object")
        record = row.get("attributes", row)
        if not isinstance(record, dict):
            raise LookupError("parse_error", "Invalid DNS attributes")
        host = record.get("host_name", record.get("hostname", record.get("subdomain", record.get("domain", ""))))
        ip = record.get("ip_address", record.get("address", record.get("value", "")))
        # Only VT resolution objects have an implicit A/AAAA record type.
        rrtype = record.get("type", record.get("record_type", ""))
        if implicit_resolution_type and row.get("type") == "resolution" and not rrtype:
            rrtype = "AAAA" if ":" in str(ip) else "A"
        if rrtype not in {"A", "AAAA"}:
            return
        facts = {"domain": host, "ip": ip, "record_type": rrtype}
        kind, value = ("domain", host) if self.ioc.type in {"ipv4", "ipv6"} else ("ipv6" if rrtype == "AAAA" else "ipv4", ip)
        self.emit(kind, value, locator, row, "dns_record", facts,
             record.get("date", record.get("last", record.get("timestamp", ""))))
    def url_record(self, url, locator, record):
        if not isinstance(url, str):
            return
        try:
            url = normalize("url", url)
            host = normalize("domain", urlsplit(url).hostname or "")
        except ValueError:
            return
        kind, value = ("url", url) if self.method.operation == "urls" else ("domain", host)
        self.emit(kind, value, locator, record, "url_host", {"url": url})



def read_json(document):
    try:
        data = json.loads(document.body)
    except (ValueError, TypeError) as exc:
        raise LookupError("parse_error", "Response is not valid JSON") from exc
    if not isinstance(data, dict):
        raise LookupError("parse_error", "Expected a provider object")
    if data.get("error") or (isinstance(data.get("status"), int) and data["status"] >= 400):
        raise LookupError("provider_error", "Provider returned an error object")
    return data


def parse_html(builder, *, section_id=None, completed_empty=False):
    method, document, result = builder.method, builder.document, builder.result
    parser = ResultTables(section_id)
    parser.feed(document.body)
    if document.diagnostics.get("terminal_state") == "timeout":
        raise LookupError("loading_page", "Requested provider response did not complete before the deadline")
    if parser.busy:
        raise LookupError("loading_page", "Requested result section is still loading")
    recognized = False
    loading_result = False
    for t, table in enumerate(parser.tables):
        if not table:
            continue
        headers = [h.lower().strip() for h in table[0]]
        if any("loading" in " ".join(row).lower() for row in table[1:]):
            loading_result = True
        def column(names):
            return next((headers.index(name) for name in names if name in headers), None)
        host_col = column(("domain", "hostname", "host name"))
        ip_col = column(("address", "ip address", "ip"))
        type_col = column(("type", "record type", "query type"))
        date_col = column(("date", "last seen"))
        if method.operation == "dns" and None not in (host_col, ip_col, type_col):
            recognized = True
            for r, row in enumerate(table[1:], 1):
                if not row or len(row) <= max(host_col, ip_col, type_col):
                    continue
                record = {"domain": row[host_col], "address": row[ip_col], "type": row[type_col]}
                if date_col is not None and date_col < len(row):
                    record["date"] = row[date_col]
                builder.dns(record, f"table[{t}].row[{r}]")
        url_col = column(("url", "urls"))
        if method.operation == "urls" and url_col is not None:
            recognized = True
            for r, row in enumerate(table[1:], 1):
                if len(row) > url_col:
                    builder.url_record(row[url_col], f"table[{t}].row[{r}]", " | ".join(row))
    text = " ".join(parser.text).lower()
    if not recognized and section_id:
        shell = ResultTables()
        shell.feed(document.body)
        text = " ".join(shell.text).lower()
    if recognized and loading_result:
        raise LookupError("loading_page", "Result table is still loading")
    if not recognized:
        if any(token in text for token in ("verify you are human", "captcha", "checking your browser", "just a moment")):
            raise LookupError("challenge", "Provider requires an interactive challenge")
        if any(token in text for token in ("please enable javascript", "loading...")):
            raise LookupError("loading_page", "Result data has not rendered")
        if any(token in text for token in ("sign in to continue", "login required")):
            raise LookupError("login_required", "Provider requires login")
        raise LookupError("parse_error", "No recognized result section; not treated as an empty lookup")
    result.complete = "limited access" not in text
    if recognized and not result.observations and not any(len(t) > 1 for t in parser.tables):
        if not completed_empty and not any(token in text for token in ("no entries found", "no results", "no records")):
            raise LookupError("loading_page", "Empty table has no completed-empty signal")
    if section_id:
        # OTX's HTML table can omit pagination controls or total counts.
        # JSON carries has_next; HTML alone cannot establish full coverage.
        result.complete = False
        result.reason = "html_coverage_unverified"
    for href, label, rel in parser.links:
        if rel == "next" or label.lower() in {"next", "next page", "›", "»"}:
            target = urljoin(document.url, href)
            if urlsplit(target).path == urlsplit(document.url).path and target != document.url:
                result.next_url = target
                break
    return finish_page(builder)


def finish_json(builder, data):
    document, result = builder.document, builder.result
    links = data.get("links") or {}
    if isinstance(links, dict) and links.get("next"):
        result.next_url = urljoin(document.url, links["next"])
    elif data.get("has_next"):
        page = int(parse_qs(urlsplit(document.url).query).get("page", [1])[0])
        result.next_url = _next_page(document.url, page + 1)
    result.complete = not bool(data.get("limited", False))
    return finish_page(builder)


def finish_page(builder):
    method, document, result = builder.method, builder.document, builder.result
    if result.next_url and not allowed_url(method.source, result.next_url):
        raise LookupError("unsafe_pagination", "Pagination left the provider host")
    # Do not allow a provider next link to switch to a different indicator.
    if result.next_url and urlsplit(result.next_url).path.rstrip("/") != urlsplit(document.url).path.rstrip("/"):
        raise LookupError("unsafe_pagination", "Pagination changed the lookup endpoint")
    return result

def dns_rows(builder, rows, prefix, *, implicit_resolution_type=False):
    if not isinstance(rows, list):
        raise LookupError("parse_error", "Missing DNS result array")
    for index, row in enumerate(rows):
        builder.dns(row, f"{prefix}[{index}]", implicit_resolution_type=implicit_resolution_type)


def url_rows(builder, rows, prefix):
    if not isinstance(rows, list):
        raise LookupError("parse_error", "Missing URL result array")
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            raise LookupError("parse_error", "URL result must be an object")
        attrs = row.get("attributes", row)
        builder.url_record(attrs.get("url", ""), f"{prefix}[{index}]", row)


def country_record(builder, address, attrs, locator):
    if not isinstance(attrs, dict):
        raise LookupError("parse_error", "Invalid country attributes")
    country = attrs.get("country_code", attrs.get("country"))
    if not country:
        if normalize(builder.ioc.type, address) != normalize(builder.ioc.type, builder.ioc.value):
            raise LookupError("invalid_response", "Country response belongs to a different IP")
        builder.result.reason = "country_unavailable"
        return
    if country:
        facts = {"ip": address, "country": country}
        builder.emit("geo_location", country, locator, facts, "ip_country", facts)


def url_details(builder, attrs, locator):
    if not isinstance(attrs, dict):
        raise LookupError("parse_error", "Invalid URL detail attributes")
    url = attrs.get("url") or attrs.get("indicator")
    if not isinstance(url, str):
        raise LookupError("parse_error", "Missing URL identity")
    try:
        if normalize("url", url) != normalize("url", builder.ioc.value):
            raise LookupError("parse_error", "URL details belong to another IOC")
    except ValueError as exc:
        raise LookupError("parse_error", "Invalid URL identity") from exc
    builder.url_record(url, locator, {"url": url})
    root_locator = locator.rsplit(".", 1)[0]
    outgoing = attrs.get("outgoing_links", [])
    if not isinstance(outgoing, list):
        raise LookupError("parse_error", "Invalid outgoing URL list")
    for index, link in enumerate(outgoing):
        builder.emit("url", link, f"{root_locator}.outgoing_links[{index}]", {"url": url, "outgoing_link": link},
                     "url_link", {"from_url": url, "to_url": link, "kind": "outgoing_link"})
    chain = attrs.get("redirection_chain", [])
    if not isinstance(chain, list):
        raise LookupError("parse_error", "Invalid redirection chain")
    only_origin = chain == [url]
    chain = [u for u in chain if u != url]
    final = attrs.get("last_final_url")
    # An absent chain does not prove the final destination is an immediate hop.
    first = chain[0] if chain else (final if only_origin else None)
    if first and first != url:
        builder.emit("url", first, root_locator + ".redirection_chain", {"url": url, "redirection_chain": attrs.get("redirection_chain"), "last_final_url": final},
                     "url_link", {"from_url": url, "to_url": first, "kind": "redirect"})
