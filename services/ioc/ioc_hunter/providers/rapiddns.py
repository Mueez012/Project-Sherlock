"""rapiddns capabilities, request routes and response field mappings."""
import re
from urllib.parse import quote, unquote, urlsplit, parse_qs
from ..method_spec import MethodSpec, supported_method
from ..models import IOC, normalize
from ..transport.models import Document, FetchRequest, allowed_url
from .base import ParsedPage
from .common import ObservationBuilder, ResultTables, read_json, parse_html, finish_json, dns_rows

source = "rapiddns"
PRIMARY_TRANSPORT = "http"
API_KEY_ENV = ""
METHODS = (
    supported_method(source, input_type="domain", output_type="ipv4", operation="dns"),
    supported_method(source, input_type="ipv4", output_type="domain", operation="dns"),
    supported_method(source, input_type="domain", output_type="ipv6", operation="dns"),
    supported_method(source, input_type="ipv6", output_type="domain", operation="dns"),
)

def requests_for(ioc: IOC, method: MethodSpec, api_key="") -> list[tuple[str, FetchRequest]]:
    value = quote(ioc.value, safe="")
    op = method.operation
    route = "subdomain" if ioc.type == "domain" else "sameip"
    page = f"https://rapiddns.io/{route}/{value}?page=1"
    return [("http", FetchRequest(source, page, op)),
            ("browser", FetchRequest(source, page, op, (f"/api/search/{value}",)))]


def _completed_empty(ioc: IOC, document: Document) -> bool:
    """Recognize RapidDNS's query-scoped, server-rendered Total: 0 result.

    The empty table alone is insufficient. Require the exact queried identity
    both in the provider URL and in the result container, one zero counter,
    a recognized empty DNS table and no result loading state. Guest limits are
    still handled by parse_html and do not become a claim of full coverage.
    """
    if ioc.type not in {"domain", "ipv4", "ipv6"} or not allowed_url(source, document.url):
        return False
    parts = urlsplit(document.url)
    route = "subdomain" if ioc.type == "domain" else "sameip"
    prefix = f"/{route}/"
    path = unquote(parts.path).rstrip("/")
    if not path.startswith(prefix) or parse_qs(parts.query).get("page", ["1"]) != ["1"]:
        return False
    try:
        query = normalize(ioc.type, ioc.value)
        if normalize(ioc.type, path[len(prefix):]) != query:
            return False
    except ValueError:
        return False
    result = ResultTables(section_id="result")
    result.feed(document.body)
    if result.busy:
        return False
    text = " ".join(" ".join(result.text).split())
    blockers = (
        "verify you are human", "captcha", "checking your browser", "just a moment",
        "please enable javascript", "sign in to continue", "login required", "access denied",
    )
    if any(marker in text.lower() for marker in blockers):
        return False
    if re.search(r"\b(?:loading|processing|retrieving)\b|\bplease\s+wait\b", text, re.I):
        return False
    if re.findall(r"\bTotal\s*:\s*([0-9][0-9,.]*)\b", text, re.I) != ["0"]:
        return False
    identity_visible = False
    for value in result.text:
        try:
            if normalize(ioc.type, value) == query:
                identity_visible = True
                break
        except ValueError:
            continue
    if not identity_visible or len(result.tables) != 1:
        return False
    table = result.tables[0]
    return len(table) == 1 and {"domain", "address", "type"} <= {
        heading.lower().strip() for heading in table[0]
    }


def parse_document(ioc: IOC, method: MethodSpec, document: Document) -> ParsedPage:
    builder = ObservationBuilder(ioc, method, document)
    if document.format != "json":
        return parse_html(builder, completed_empty=_completed_empty(ioc, document))
    data = read_json(document)
    container = data.get("data", {})
    rows = container.get("data", container.get("records")) if isinstance(container, dict) else None
    dns_rows(builder, rows, "$.data.data")
    return finish_json(builder, data)
