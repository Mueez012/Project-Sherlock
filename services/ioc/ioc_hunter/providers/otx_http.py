"""Query-bound HTTP redirect fields from OTX's URL report page."""
import re
from urllib.parse import parse_qs, unquote, urljoin, urlsplit

from ..models import normalize
from ..transport.models import LookupError, allowed_url
from .common import read_json


REDIRECT_CODES = {301, 302, 303, 307, 308}
STATUS = re.compile(r"^HTTP/(?:1\.[01]|2(?:\.0)?|3(?:\.0)?)[ \t]+([0-9]{3})(?=[ \t]|$)")
FIELD = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+:")
LOCATION = re.compile(r"(?<!\S)Location[ \t]*:", re.I)


def parse_http_scans(builder):
    """Return only a redirect explicitly recorded in the requested URL's headers."""
    method, query, document = builder.method, builder.ioc, builder.document
    if (method.source, method.operation, method.input_type, method.output_type, query.type) != (
            "alienvault", "http_scans", "url", "url", "url"):
        raise LookupError("parse_error", "HTTP scans require an OTX URL-to-URL method")
    if document.format != "json":
        raise LookupError("parse_error", "Requested HTTP-scan JSON response was not captured")
    if not allowed_url("alienvault", document.url):
        raise LookupError("invalid_response", "HTTP-scan response left the OTX source")
    parts = urlsplit(document.url)
    prefix = "/otxapi/indicators/url/http_scans/"
    if not parts.path.startswith(prefix):
        raise LookupError("invalid_response", "Response is not the requested OTX HTTP-scan operation")
    try:
        url = normalize("url", query.value)
        response_url = normalize("url", unquote(parts.path[len(prefix):], errors="strict"))
    except (ValueError, UnicodeError) as exc:
        raise LookupError("invalid_response", "Invalid HTTP-scan URL identity") from exc
    if response_url != url:
        raise LookupError("invalid_response", "HTTP-scan response belongs to another URL")
    parameters = parse_qs(parts.query)
    if parameters.get("cursor") or parameters.get("page", ["1"]) != ["1"]:
        raise LookupError("invalid_response", "Unexpected HTTP-scan continuation response")
    data = read_json(document, reject_duplicate_keys=True)
    rows, count = data.get("data"), data.get("count")
    if not isinstance(rows, list) or type(count) is not int or count < 0:
        raise LookupError("parse_error", "HTTP-scan response lacks a result array and explicit count")
    if count < len(rows):
        raise LookupError("parse_error", "HTTP-scan count conflicts with returned rows")
    redirects = []
    for index, row in enumerate(rows):
        if (not isinstance(row, dict) or not isinstance(row.get("key"), str)
                or not isinstance(row.get("name"), str) or "value" not in row):
            raise LookupError("parse_error", "Malformed HTTP-scan result row")
        if row["key"].strip().lower() != "header":
            continue
        target = _redirect_target(row["value"], url)
        if target is not None:
            redirects.append((index, row, target))
    # Validate the complete captured container before publishing observations.
    for index, row, target in redirects:
        builder.emit("url", target, f"$.data[{index}].value", row, "url_link",
                     {"from_url": url, "to_url": target, "kind": "redirect"})
    if count > len(rows):
        builder.result.complete = False
        builder.result.reason = "http_scan_result_truncated"
    elif not builder.result.observations:
        builder.result.reason = "redirect_unavailable"
    return builder.result


def _redirect_target(header, url):
    if not isinstance(header, str) or not header.strip():
        raise LookupError("parse_error", "Missing HTTP response header text")
    if re.search(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]|\r(?!\n)", header):
        raise LookupError("parse_error", "Malformed HTTP response header text")
    # A body following an actual header terminator is never searched for links.
    text = header.replace("\r\n", "\n").split("\n\n", 1)[0].strip()
    lines = text.split("\n")
    status = STATUS.match(lines[0])
    if status is None:
        raise LookupError("parse_error", "Missing explicit HTTP response status")
    locations = []
    if len(lines) > 1:
        for line in lines[1:]:
            if not FIELD.match(line):
                raise LookupError("parse_error", "Malformed HTTP response header line")
            name, value = line.split(":", 1)
            if name.lower() == "location":
                locations.append(value.strip())
    else:
        # OTX's captured representation flattens header lines into spaces. Only
        # the bounded Location value is usable, never arbitrary URL-like text.
        matches = list(LOCATION.finditer(text, status.end()))
        if len(matches) > 1:
            raise LookupError("parse_error", "Duplicate HTTP Location headers")
        if matches:
            remainder = text[matches[0].end():].strip()
            pieces = remainder.split(None, 1)
            if not pieces or (len(pieces) > 1 and not FIELD.match(pieces[1])):
                raise LookupError("parse_error", "Malformed HTTP Location value")
            locations.append(pieces[0])
    if len(locations) > 1:
        raise LookupError("parse_error", "Duplicate HTTP Location headers")
    if not locations:
        return None
    location = locations[0]
    if not location or re.search(r"[\s<>\"\\]", location):
        raise LookupError("parse_error", "Malformed HTTP Location value")
    try:
        target = normalize("url", urljoin(url, location))
    except ValueError as exc:
        raise LookupError("parse_error", "Invalid HTTP redirect URL") from exc
    return target if int(status.group(1)) in REDIRECT_CODES else None
