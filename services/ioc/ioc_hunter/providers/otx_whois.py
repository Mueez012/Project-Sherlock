"""OTX's query-bound WHOIS rows; no graph admission or ownership scoring."""
from urllib.parse import parse_qs, unquote, urlsplit

from ..models import normalize
from ..transport.models import LookupError, allowed_url
from .common import read_json


def parse_whois(builder):
    """Extract concrete addresses only from the report's labelled email rows.

    Observed response: {data: [{key, name, value}], count, related}. `related`
    contains other domains and is deliberately outside this operation.
    """
    method, query, document = builder.method, builder.ioc, builder.document
    if (method.source, method.operation, method.input_type, method.output_type, query.type) != (
            "alienvault", "whois", "domain", "email", "domain"):
        raise LookupError("parse_error", "WHOIS operation requires an OTX domain-to-email method")
    if document.format != "json":
        raise LookupError("parse_error", "Requested WHOIS JSON response was not captured")
    if not allowed_url("alienvault", document.url):
        raise LookupError("invalid_response", "WHOIS response left the OTX source")
    parts = urlsplit(document.url)
    prefix = "/otxapi/indicators/domain/whois/"
    path = parts.path.rstrip("/")
    if not path.startswith(prefix):
        raise LookupError("invalid_response", "Response is not the requested OTX WHOIS operation")
    try:
        domain = normalize("domain", query.value)
        response_domain = normalize("domain", unquote(path[len(prefix):], errors="strict"))
    except (ValueError, UnicodeError) as exc:
        raise LookupError("invalid_response", "Invalid WHOIS response identity") from exc
    if response_domain != domain:
        raise LookupError("invalid_response", "WHOIS response belongs to another domain")
    parameters = parse_qs(parts.query)
    if parameters.get("cursor") or parameters.get("page", ["1"]) != ["1"]:
        raise LookupError("invalid_response", "Unexpected WHOIS continuation response")
    data = read_json(document, reject_duplicate_keys=True)
    rows, count = data.get("data"), data.get("count")
    if not isinstance(rows, list) or type(count) is not int or count < 0:
        raise LookupError("parse_error", "WHOIS response lacks a result array and explicit count")
    if count < len(rows):
        raise LookupError("parse_error", "WHOIS count conflicts with returned rows")
    # Validate the entire container and explicit identity before emitting any
    # observation, including rows following an otherwise valid email field.
    for row in rows:
        if (not isinstance(row, dict) or not isinstance(row.get("key"), str)
                or not row["key"].strip() or not isinstance(row.get("name"), str)
                or not row["name"].strip() or "value" not in row):
            raise LookupError("parse_error", "Malformed WHOIS result row")
        if row["key"].strip().lower() == "domain_name":
            try:
                recorded_domain = normalize("domain", row["value"])
            except (ValueError, TypeError) as exc:
                raise LookupError("parse_error", "Malformed WHOIS domain-name field") from exc
            if recorded_domain != domain:
                raise LookupError("invalid_response", "WHOIS domain-name field belongs to another domain")
    for index, row in enumerate(rows):
        field = row["key"].strip().lower()
        if field not in {"email", "emails"}:
            continue
        value = row["value"]
        if (not isinstance(value, str) or value.count("@") != 1
                or any(ord(char) < 32 or ord(char) == 127 for char in value)):
            continue
        try:
            email = normalize("email", value)
        except (ValueError, TypeError, AttributeError):
            # Redaction notices and malformed individual IOC values are not
            # source errors and do not invalidate other concrete email rows.
            continue
        facts = {"domain": domain, "email": email, "field": field}
        builder.emit("email", email, f"$.data[{index}].value", row, "whois_email", facts)
    if count > len(rows):
        builder.result.complete = False
        builder.result.reason = "whois_result_truncated"
    elif not builder.result.observations:
        builder.result.reason = "email_unavailable"
    return builder.result
