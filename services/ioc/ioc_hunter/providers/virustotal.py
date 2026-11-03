"""virustotal capabilities, request routes and response field mappings."""
import base64
from hashlib import sha256
from urllib.parse import quote
from ..method_spec import MethodSpec, supported_method
from ..models import IOC
from ..transport.models import Document, FetchRequest
from .base import ParsedPage
from .common import (ObservationBuilder, read_json, parse_html, finish_json,
                     dns_rows, url_rows, country_record, url_details)

source = "virustotal"
PRIMARY_TRANSPORT = "browser"
API_KEY_ENV = "VT_API_KEY"
METHODS = (
    supported_method(source, input_type="domain", output_type="ipv4", operation="dns"),
    supported_method(source, input_type="ipv4", output_type="domain", operation="dns"),
    supported_method(source, input_type="domain", output_type="ipv6", operation="dns", baseline=False),
    supported_method(source, input_type="ipv6", output_type="domain", operation="dns", baseline=False),
    supported_method(source, input_type="domain", output_type="url", operation="urls"),
    supported_method(source, input_type="url", output_type="domain", operation="url_details"),
    supported_method(source, input_type="ipv4", output_type="geo_location", operation="geo"),
    supported_method(source, input_type="ipv6", output_type="geo_location", operation="geo", baseline=False),
    supported_method(source, input_type="url", output_type="url", operation="url_details"),
)

def _url_id(value):
    return base64.urlsafe_b64encode(value.encode()).decode().rstrip("=")

def requests_for(ioc: IOC, method: MethodSpec, api_key="") -> list[tuple[str, FetchRequest]]:
    value = quote(ioc.value, safe="")
    op = method.operation
    kind = "domains" if ioc.type == "domain" else "urls" if ioc.type == "url" else "ip_addresses"
    object_id = _url_id(ioc.value) if ioc.type == "url" else value
    # VT UI uses SHA256 URL IDs; public API also accepts unpadded base64url IDs.
    ui_id = sha256(ioc.value.encode()).hexdigest() if ioc.type == "url" else value
    ui_kind = "domain" if ioc.type == "domain" else "url" if ioc.type == "url" else "ip-address"
    section = "resolutions" if op == "dns" else "urls" if op == "urls" else ""
    suffix = "/" + section if section else ""
    ui = f"https://www.virustotal.com/gui/{ui_kind}/{ui_id}/" + ("relations" if section else "details")
    paths = (f"/ui/{kind}/{ui_id}{suffix}", f"/api-proxy/ui/{kind}/{ui_id}{suffix}",
             f"/api/v3/{kind}/{ui_id}{suffix}")
    result = [("browser", FetchRequest(source, ui, op, paths, identity_type=ioc.type))]
    if api_key and op != "urls":  # Domain URLs is a premium API relationship.
        result.append(("http", FetchRequest(source, f"https://www.virustotal.com/api/v3/{kind}/{object_id}{suffix}",
                                           op, headers={"x-apikey": api_key})))
    return result

def parse_document(ioc: IOC, method: MethodSpec, document: Document) -> ParsedPage:
    builder = ObservationBuilder(ioc, method, document)
    if document.format != "json":
        return parse_html(builder)
    data = read_json(document)
    if method.operation == "dns":
        dns_rows(builder, data.get("data"), "$.data", implicit_resolution_type=True)
    elif method.operation == "urls":
        url_rows(builder, data.get("data"), "$.data")
    else:
        obj = data.get("data")
        if not isinstance(obj, dict) or not isinstance(obj.get("attributes"), dict) or not obj.get("id"):
            from ..transport.models import LookupError
            raise LookupError("parse_error", "Missing provider object identity or attributes")
        attrs = obj["attributes"]
        if method.operation == "geo":
            country_record(builder, obj["id"], attrs, "$.data.attributes.country")
        else:
            url_details(builder, attrs, "$.data.attributes.url")
    return finish_json(builder, data)
