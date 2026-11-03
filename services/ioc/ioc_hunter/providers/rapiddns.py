"""rapiddns capabilities, request routes and response field mappings."""
from urllib.parse import quote
from ..method_spec import MethodSpec, supported_method
from ..models import IOC
from ..transport.models import Document, FetchRequest
from .base import ParsedPage
from .common import ObservationBuilder, read_json, parse_html, finish_json, dns_rows

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


def parse_document(ioc: IOC, method: MethodSpec, document: Document) -> ParsedPage:
    builder = ObservationBuilder(ioc, method, document)
    if document.format != "json":
        return parse_html(builder)
    data = read_json(document)
    container = data.get("data", {})
    rows = container.get("data", container.get("records")) if isinstance(container, dict) else None
    dns_rows(builder, rows, "$.data.data")
    return finish_json(builder, data)
