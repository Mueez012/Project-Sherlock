"""Hybrid Analysis HAQL and rendered search discovery; no network execution.

The current browser search owns its CSRF/session handling. Its rendered result
links are navigation handles, not public IOC outputs. A file-content match is
used for discovery only; runtime observations are read from the sample report.
"""
from html.parser import HTMLParser
import json
import re
from urllib.parse import parse_qs, urljoin, urlsplit

from ..models import HASH_LENGTHS, normalize
from ..transport.models import LookupError, allowed_url


def haql_query(ioc) -> str:
    """Quote literal input so filename/content data cannot add HAQL clauses."""
    value = normalize(ioc.type, ioc.value)
    field = ioc.type if ioc.type in HASH_LENGTHS else "filename" if ioc.type == "filename" else "content"
    if ioc.type not in {*HASH_LENGTHS, "filename", "registry", "command_api"}:
        raise LookupError("invalid_request", "Unsupported Hybrid Analysis search input")
    return field + ":" + json.dumps(value, ensure_ascii=False)


class SearchHTML(HTMLParser):
    """Read the actual result section, query input and visible coverage labels."""
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.query_values = []
        self.links = []
        self.text = []
        self.result_text = []
        self.results = 0
        self.search_form = 0
        self.hidden = 0
        self.result_sections = 0
        self.next_enabled = False

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag in {"script", "style"}:
            self.hidden += 1
        if tag == "form" and (self.search_form or attrs.get("role") == "search"):
            self.search_form += 1
        if tag == "input" and self.search_form and attrs.get("role") == "combobox":
            self.query_values.append(attrs.get("value", ""))
        if tag == "section":
            classes = attrs.get("class", "").split()
            is_result = any(token.endswith("_results") for token in classes)
            if self.results or is_result:
                self.results += 1
                if is_result:
                    self.result_sections += 1
        if tag == "a" and self.results:
            self.links.append(attrs.get("href", ""))
        label = attrs.get("aria-label", "").strip().lower()
        if self.results and tag in {"button", "a"} and label in {"next", "next page"}:
            self.next_enabled |= "disabled" not in attrs and attrs.get("aria-disabled") != "true"

    def handle_endtag(self, tag):
        if tag in {"script", "style"}:
            self.hidden = max(0, self.hidden - 1)
        if tag == "section" and self.results:
            self.results -= 1
        if tag == "form" and self.search_form:
            self.search_form -= 1

    def handle_data(self, text):
        if not self.hidden:
            self.text.append(text)
            if self.results:
                self.result_text.append(text)


def search_references(ioc, document) -> tuple[list[str], bool, str]:
    """Return provider-linked sample hashes and honest coverage, never IOCs."""
    if not allowed_url("hybridanalysis", document.url):
        raise LookupError("invalid_response", "Hybrid Analysis search left the provider")
    parts = urlsplit(document.url)
    expected_query = haql_query(ioc)
    if parts.path.rstrip("/") != "/search" or parse_qs(parts.query).get("q") != [expected_query]:
        raise LookupError("invalid_response", "Hybrid Analysis search belongs to another query")
    if document.format != "html":
        raise LookupError("parse_error", "Expected the completed rendered Hybrid Analysis search")
    parser = SearchHTML()
    parser.feed(document.body)
    text = " ".join(" ".join(parser.text).split())
    lowered = text.lower()
    for markers, status in (
        (("verify you are human", "checking your browser", "captcha", "just a moment"), "challenge"),
        (("login required", "sign in to continue", "please log in to use", "authentication required"), "login_required"),
        (("access denied", "requires a vetted account", "insufficient permissions"), "access_denied"),
        (("invalid query", "query syntax error", "invalid haql"), "invalid_request"),
    ):
        if any(marker in lowered for marker in markers):
            raise LookupError(status, "Hybrid Analysis search did not provide usable results")
    if not parser.result_sections or expected_query not in parser.query_values:
        raise LookupError("parse_error", "Missing query-bound Hybrid Analysis result section")
    references = []
    for href in parser.links:
        target = urljoin(document.url, href)
        if not allowed_url("hybridanalysis", target):
            continue
        match = re.fullmatch(r"/sample/([0-9a-fA-F]{64})/?", urlsplit(target).path)
        if match:
            value = normalize("sha256", match.group(1))
            if value not in references:
                references.append(value)
    empty = "no results found" in " ".join(parser.result_text).lower()
    if not references and not empty:
        raise LookupError("loading_page", "Hybrid Analysis search has no completed results or empty signal")
    # The observed UI defaults to one hour. Do not turn that window's empty
    # result into a claim that no historical sample exists.
    window = re.search(r"\bLast\s+(?:\d+\s+)?(?:hour|day|week|month|year)s?\b", text, re.I)
    if window:
        return references, False, "search_time_window_limited"
    if parser.next_enabled:
        return references, False, "search_pagination_unverified"
    # No total-count/pagination contract was observed for positive searches.
    return references, False, "search_coverage_unverified"
