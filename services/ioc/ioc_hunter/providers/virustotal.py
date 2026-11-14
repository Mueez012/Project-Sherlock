"""virustotal capabilities, request routes and response field mappings."""
import base64
from dataclasses import replace
from hashlib import sha256
from urllib.parse import quote, urlsplit
from ..method_spec import MethodSpec, supported_method
from ..models import HASH_LENGTHS, IOC, normalize
from ..transport.models import Document, FetchRequest, LookupError, allowed_url
from .base import FollowUp, ParsedPage
from .common import (ObservationBuilder, read_json, parse_html, finish_json,
                     dns_rows, url_rows, country_record, url_details, url_filename)
from .vt_network import network_fields

source = "virustotal"
PRIMARY_TRANSPORT = "browser"
API_KEY_ENV = "VT_API_KEY"
HASH_TYPES = tuple(HASH_LENGTHS)
BEHAVIOR_FIELDS = ("command_executions", "calls_highlighted", "invokes")
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
    supported_method(source, input_type="url", output_type="filename", operation="url_details"),
    supported_method(source, input_type="md5", output_type="command_api", operation="file_behavior"),
    supported_method(source, input_type="sha1", output_type="command_api", operation="file_behavior"),
    supported_method(source, input_type="sha256", output_type="command_api", operation="file_behavior"),
    supported_method(source, input_type="ipv4", output_type="command_api", operation="ip_file_behavior"),
    supported_method(source, input_type="ipv4", output_type="ipv4", operation="ip_file_behavior"),
)

def _url_id(value):
    return base64.urlsafe_b64encode(value.encode()).decode().rstrip("=")

def requests_for(ioc: IOC, method: MethodSpec, api_key="") -> list[tuple[str, FetchRequest]]:
    if method.operation == "ip_file_behavior":
        return _communicating_file_requests(ioc, api_key)
    if method.operation == "file_behavior":
        if ioc.type not in HASH_TYPES:
            raise LookupError("invalid_request", "File behavior requires an MD5, SHA-1 or SHA-256 hash")
        value = normalize(ioc.type, ioc.value)
        result = [("browser", FetchRequest(
            source, f"https://www.virustotal.com/gui/file/{value}/behavior", method.operation,
            (f"/ui/files/{value}/behaviours", "/ui/files/{page_id}/behaviours"),
            identity_type=ioc.type, integration_version="3",
            page_identity_pattern=r"/gui/file/([0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64})(?:/behavior)?/?"))]
        if api_key:
            result.append(("http", FetchRequest(
                source, f"https://www.virustotal.com/api/v3/files/{value}/behaviour_summary",
                method.operation, headers={"x-apikey": api_key}, identity_type=ioc.type,
                integration_version="3")))
        return result
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
    if method.operation == "ip_file_behavior":
        return _ip_file_behavior(builder)
    if method.operation == "file_behavior":
        return _file_behavior(builder)
    if document.format != "json":
        return parse_html(builder)
    data = read_json(document, reject_duplicate_keys=method.output_type == "filename")
    if method.operation == "dns":
        dns_rows(builder, data.get("data"), "$.data", implicit_resolution_type=True)
    elif method.operation == "urls":
        url_rows(builder, data.get("data"), "$.data")
    else:
        obj = data.get("data")
        if not isinstance(obj, dict) or not isinstance(obj.get("attributes"), dict) or not obj.get("id"):
            raise LookupError("parse_error", "Missing provider object identity or attributes")
        attrs = obj["attributes"]
        if method.operation == "geo":
            country_record(builder, obj["id"], attrs, "$.data.attributes.country")
        elif method.output_type == "filename":
            url_filename(builder, attrs, "$.data.attributes.url")
        else:
            url_details(builder, attrs, "$.data.attributes.url")
    return finish_json(builder, data)


def _file_behavior(builder: ObservationBuilder, *, file_ioc: IOC | None = None) -> ParsedPage:
    """Read page-generated sandbox reports or the optional official summary."""
    ioc, document = file_ioc or builder.ioc, builder.document
    if ioc.type not in HASH_TYPES:
        raise LookupError("invalid_request", "File behavior requires a supported file hash")
    value = normalize(ioc.type, ioc.value)
    if not allowed_url(source, document.url):
        raise LookupError("invalid_response", "File behavior response left the provider")
    if document.format != "json":
        if urlsplit(document.url).path.startswith("/gui/file/"):
            return parse_html(builder)
        raise LookupError("parse_error", "Expected JSON file behavior data")
    data = read_json(document)
    path = urlsplit(document.url).path.rstrip("/")
    if path.startswith("/ui/files/"):
        response_hash = _browser_behavior_hash(ioc, document)
        rows = data.get("data")
        if not isinstance(rows, list):
            raise LookupError("parse_error", "Missing file behavior report list")
        canonical_hash = response_hash if len(response_hash) == HASH_LENGTHS["sha256"] else ""
        for index, row in enumerate(rows):
            if not isinstance(row, dict) or row.get("type") != "file_behaviour" or not isinstance(row.get("id"), str):
                raise LookupError("parse_error", "Invalid file behavior report identity")
            report_hash, separator, sandbox = row["id"].partition("_")
            try:
                report_hash = normalize("sha256", report_hash)
            except ValueError as exc:
                raise LookupError("parse_error", "Invalid file behavior report hash") from exc
            if not separator or not sandbox:
                raise LookupError("parse_error", "Missing file behavior sandbox identity")
            if canonical_hash and canonical_hash != report_hash:
                raise LookupError("invalid_response", "Behavior report belongs to another file")
            canonical_hash = report_hash
            _selected_behavior_fields(builder, row.get("attributes"), f"$.data[{index}].attributes")
        return finish_json(builder, data)
    if path != f"/api/v3/files/{value}/behaviour_summary":
        raise LookupError("invalid_response", "Behavior summary belongs to another hash or operation")
    attributes = data.get("data")
    _selected_behavior_fields(builder, attributes, "$.data")
    return builder.result


def _browser_behavior_hash(ioc: IOC, document: Document) -> str:
    """Bind a captured response to the requested file or its actual report page."""
    value = normalize(ioc.type, ioc.value)
    parts = urlsplit(document.url).path.strip("/").split("/")
    if len(parts) != 4 or parts[:2] != ["ui", "files"] or parts[3] != "behaviours":
        raise LookupError("invalid_response", "Unexpected browser file behavior operation")
    response_hash = parts[2]
    kind = next((kind for kind, length in HASH_LENGTHS.items() if len(response_hash) == length), "")
    try:
        response_hash = normalize(kind, response_hash)
    except ValueError as exc:
        raise LookupError("invalid_response", "Invalid browser file identity") from exc
    if response_hash == value:
        return response_hash
    page_url = document.diagnostics.get("page_url", "")
    request_url = document.diagnostics.get("request_url", "")
    if not allowed_url(source, page_url) or not allowed_url(source, request_url):
        raise LookupError("invalid_response", "Missing original file navigation identity")
    page_parts = urlsplit(page_url).path.strip("/").split("/")
    if (page_parts not in (["gui", "file", response_hash], ["gui", "file", response_hash, "behavior"])
            or urlsplit(request_url).path.rstrip("/") != f"/gui/file/{value}/behavior"
            or ioc.type == "sha256"):
        raise LookupError("invalid_response", "Behavior response does not match the requested file page")
    return response_hash


def _behavior_fields(builder: ObservationBuilder, attributes, prefix: str, *,
                     fact_type="file_behavior", extra_facts=None) -> None:
    """Share command/API cleaning between browser reports and API summaries."""
    if not isinstance(attributes, dict):
        raise LookupError("parse_error", "Missing file behavior fields")
    if "attributes" in attributes or "error" in attributes:
        raise LookupError("parse_error", "Expected flat file behavior fields")
    for field in BEHAVIOR_FIELDS:
        entries = attributes.get(field, [])
        if not isinstance(entries, list):
            raise LookupError("parse_error", f"Invalid behavior field: {field}")
        for index, entry in enumerate(entries):
            if not isinstance(entry, str):
                raise LookupError("parse_error", f"Invalid entry in behavior field: {field}")
            command = entry.strip()
            if not command:
                continue
            builder.emit("command_api", command, f"{prefix}.{field}[{index}]", {field: entry},
                         fact_type, {**(extra_facts or {}), "field": field, "value": command},
                         attributes.get("analysis_date", ""))


def _communicating_file_requests(ioc: IOC, api_key="") -> list[tuple[str, FetchRequest]]:
    """Discover files through the IP report, without an Intelligence search."""
    if ioc.type != "ipv4":
        raise LookupError("invalid_request", "Communicating-file discovery requires IPv4")
    value = normalize("ipv4", ioc.value)
    suffix = f"ip_addresses/{value}/communicating_files"
    context = {"stage": "communicating_files", "query_ip": value}
    result = [("browser", FetchRequest(
        source, f"https://www.virustotal.com/gui/ip-address/{value}/relations",
        "ip_file_behavior", (f"/ui/{suffix}", f"/api-proxy/ui/{suffix}", f"/api/v3/{suffix}"),
        identity_type="ipv4", integration_version="4", context=context))]
    if api_key:
        result.append(("http", FetchRequest(
            source, f"https://www.virustotal.com/api/v3/{suffix}", "ip_file_behavior",
            headers={"x-apikey": api_key}, identity_type="ipv4", integration_version="4", context=context)))
    return result


def _ip_file_behavior(builder: ObservationBuilder) -> ParsedPage:
    """Compose existing report reads; extraction does not admit graph edges."""
    ioc, method, document = builder.ioc, builder.method, builder.document
    if ioc.type != "ipv4":
        raise LookupError("invalid_request", "IP behavior discovery requires IPv4")
    query_ip = normalize("ipv4", ioc.value)
    context = document.diagnostics.get("request_context", {})
    if not isinstance(context, dict) or context.get("query_ip") != query_ip:
        raise LookupError("invalid_response", "Missing query-bound IP discovery stage")
    if context.get("stage") == "file_behavior":
        try:
            file_hash = normalize("sha256", context.get("file_hash", ""))
        except ValueError as exc:
            raise LookupError("invalid_response", "Missing discovered file identity") from exc
        return _file_behavior(builder, file_ioc=IOC(file_hash, "sha256"))
    if context.get("stage") != "communicating_files" or not allowed_url(source, document.url):
        raise LookupError("invalid_response", "Unexpected IP discovery stage")
    if document.format != "json":
        return parse_html(builder)
    suffix = f"ip_addresses/{query_ip}/communicating_files"
    if urlsplit(document.url).path.rstrip("/") not in {
            f"/ui/{suffix}", f"/api-proxy/ui/{suffix}", f"/api/v3/{suffix}"}:
        raise LookupError("invalid_response", "Communicating-file response belongs to another IP")
    data = read_json(document)
    rows = data.get("data")
    if not isinstance(rows, list):
        raise LookupError("parse_error", "Missing communicating-file list")
    seen = set()
    for row in rows:
        if not isinstance(row, dict) or row.get("type") != "file":
            raise LookupError("parse_error", "Invalid communicating-file object")
        try:
            file_hash = normalize("sha256", row.get("id", ""))
        except ValueError as exc:
            raise LookupError("parse_error", "Invalid communicating-file hash") from exc
        if file_hash in seen:
            continue
        seen.add(file_hash)
        file_ioc = IOC(file_hash, "sha256")
        file_method = replace(method, input_type="sha256", output_type="command_api", operation="file_behavior")
        builder.result.followups.append(FollowUp(
            f"virustotal:file_behavior:{file_hash}", ioc=file_ioc, method=file_method,
            context={"stage": "file_behavior", "file_hash": file_hash, "query_ip": query_ip}))
    return finish_json(builder, data)


def _selected_behavior_fields(builder: ObservationBuilder, attributes, prefix: str) -> None:
    if builder.method.operation != "ip_file_behavior":
        _behavior_fields(builder, attributes, prefix)
        return
    context = builder.document.diagnostics["request_context"]
    facts = {"discovery_ip": context["query_ip"], "file_hash": context["file_hash"]}
    if builder.method.output_type == "command_api":
        _behavior_fields(builder, attributes, prefix, fact_type="ip_file_behavior", extra_facts=facts)
    else:
        network_fields(builder, attributes, prefix, facts)
