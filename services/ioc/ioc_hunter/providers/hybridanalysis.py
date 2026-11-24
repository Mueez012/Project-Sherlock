"""Hybrid Analysis report-page adapter with shared bounded acquisition steps."""
from urllib.parse import quote

from ..method_spec import supported_method
from ..models import HASH_LENGTHS, IOC, normalize
from ..transport.models import Document, FetchRequest, LookupError
from .base import FollowUp
from .common import ObservationBuilder
from .ha_search import haql_query, search_references
from .ha_report import (read_report, command_observations, registry_observations,
                        filename_observations, url_observations)

source = "hybridanalysis"
PRIMARY_TRANSPORT = "browser"
# No direct API fallback is inferred from the legacy v2 API or key presence.
API_KEY_ENV = ""
OPERATION = "ha_report"
METHODS = tuple(
    supported_method(source, input_type=kind, output_type="command_api", operation=OPERATION, baseline=False)
    for kind in HASH_LENGTHS
) + (
    supported_method(source, input_type="filename", output_type="command_api", operation=OPERATION, baseline=False),
    supported_method(source, input_type="filename", output_type="registry", operation=OPERATION, baseline=False),
    supported_method(source, input_type="filename", output_type="url", operation=OPERATION, baseline=False),
    supported_method(source, input_type="registry", output_type="filename", operation=OPERATION, baseline=False),
    supported_method(source, input_type="command_api", output_type="registry", operation=OPERATION, baseline=False),
)


def _report_request(sample_hash):
    value = normalize("sha256", sample_hash)
    return FetchRequest(
        source, f"https://hybrid-analysis.com/sample/{value}", OPERATION,
        capture_html=True, ready_selector="script", ready_text="initialData",
        context={"stage": "report", "sample_sha256": value}, integration_version="2")


def requests_for(ioc: IOC, method, api_key=""):
    if method.operation != OPERATION:
        raise LookupError("unsupported_method", "Unknown Hybrid Analysis operation")
    if ioc.type == "sha256":
        return [("browser", _report_request(ioc.value))]
    query = haql_query(ioc)
    request = FetchRequest(
        source, "https://hybrid-analysis.com/search?q=" + quote(query, safe=""), OPERATION,
        capture_html=True,
        # The current page performs this POST while rendering its search. Its
        # access errors must not be mistaken for an unfinished/empty HTML view.
        bootstrap_paths=("/bff/proxy/search",),
        ready_selector="section[class*='_results'] a[href*='/sample/'], section[class*='_results'] h4",
        context={"stage": "search", "haql_query": query}, integration_version="2")
    return [("browser", request)]


def parse_document(ioc: IOC, method, document: Document):
    builder = ObservationBuilder(ioc, method, document)
    context = document.diagnostics.get("request_context", {})
    if not isinstance(context, dict):
        raise LookupError("invalid_response", "Invalid Hybrid Analysis acquisition context")
    stage = context.get("stage", "report" if "/sample/" in document.url else "search")
    if stage == "search":
        references, complete, reason = search_references(ioc, document)
        builder.result.complete, builder.result.reason = complete, reason
        for value in references:
            builder.result.followups.append(FollowUp(
                key="ha-report:" + value, routes=(("browser", _report_request(value)),)))
        return builder.result
    if stage != "report":
        raise LookupError("invalid_response", "Unknown Hybrid Analysis acquisition stage")
    report = read_report(document)
    sample_hash = normalize("sha256", report["sha256"])
    if context.get("sample_sha256") and normalize("sha256", context["sample_sha256"]) != sample_hash:
        raise LookupError("invalid_response", "Hybrid Analysis report changed sample identity")
    if ioc.type == "sha256" and normalize("sha256", ioc.value) != sample_hash:
        raise LookupError("invalid_response", "Hybrid Analysis report belongs to another input hash")
    runtime_match = None
    if ioc.type == "command_api":
        requested = normalize("command_api", ioc.value).casefold()
        runtime_match = next((item for item in command_observations(report)
                              if item[0].casefold() == requested), None)
        if runtime_match is None:
            builder.result.reason = "command_api_not_observed"
            _coverage(builder, report)
            return builder.result
    extractor = {"command_api": command_observations, "registry": registry_observations,
                 "filename": filename_observations, "url": url_observations}.get(method.output_type)
    if extractor is None:
        raise LookupError("unsupported_method", "Unknown Hybrid Analysis output type")
    for value, locator, row in extractor(report):
        facts = {"sample_sha256": sample_hash, "output_type": method.output_type,
                 "value": value, "field": locator, "stage": "report"}
        record = row
        if runtime_match is not None:
            facts["runtime_command"] = runtime_match[0]
            facts["runtime_locator"] = runtime_match[1]
            record = {"registry_observation": row, "runtime_observation": runtime_match[2]}
        builder.emit(method.output_type, value, locator, record, "ha_report_value", facts,
                     report.get("unified_at", ""))
    if not builder.result.observations:
        builder.result.reason = method.output_type + "_unavailable"
    _coverage(builder, report)
    return builder.result


def _coverage(builder, report):
    status = str(report.get("overall_status", "")).upper()
    if status in {"PENDING", "RUNNING", "IN_PROGRESS", "QUEUED", "PROCESSING"}:
        builder.result.complete = False
        builder.result.reason = "report_processing"
    elif status in {"ERROR", "FAILED", "FAILURE"}:
        builder.result.complete = False
        builder.result.reason = "report_incomplete"
