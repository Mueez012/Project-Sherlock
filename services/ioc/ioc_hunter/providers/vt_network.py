"""Pure extraction of IP observations from VirusTotal sandbox network fields."""
from ..models import normalize
from ..transport.models import LookupError


NETWORK_FIELDS = frozenset({
    "ip_traffic.destination_ip", "ip_traffic.source_ip", "dns_lookups.resolved_ips",
    "http_conversations.remote_ip", "ids_alerts.alert_context.src_ip",
    "ids_alerts.alert_context.dest_ip",
})


def network_fields(builder, attributes, prefix, discovery_facts):
    """Read declared fields, without deriving peers from arbitrary report text."""
    if not isinstance(attributes, dict) or "attributes" in attributes or "error" in attributes:
        raise LookupError("parse_error", "Missing flat file behavior fields")
    observed = attributes.get("analysis_date", "")

    def emit(value, locator, row, field):
        if not isinstance(value, str):
            raise LookupError("parse_error", f"Invalid network address in {field}")
        try:
            value = normalize("ipv4", value)
        except ValueError:
            # IPv6 observations and non-address placeholders are not IPv4 outputs.
            return
        builder.emit("ipv4", value, locator, row, "ip_file_network",
                     {**discovery_facts, "field": field, "value": value}, observed)

    def rows(field):
        entries = attributes.get(field, [])
        if not isinstance(entries, list):
            raise LookupError("parse_error", f"Invalid behavior field: {field}")
        for index, entry in enumerate(entries):
            if not isinstance(entry, dict):
                raise LookupError("parse_error", f"Invalid record in behavior field: {field}")
            yield index, entry

    for index, row in rows("ip_traffic"):
        for name in ("destination_ip", "source_ip"):
            if name in row:
                emit(row[name], f"{prefix}.ip_traffic[{index}].{name}", row, f"ip_traffic.{name}")
    for index, row in rows("dns_lookups"):
        addresses = row.get("resolved_ips", [])
        if not isinstance(addresses, list):
            raise LookupError("parse_error", "Invalid DNS resolved-IP list")
        for address_index, value in enumerate(addresses):
            emit(value, f"{prefix}.dns_lookups[{index}].resolved_ips[{address_index}]", row,
                 "dns_lookups.resolved_ips")
    for index, row in rows("http_conversations"):
        if "remote_ip" in row:
            emit(row["remote_ip"], f"{prefix}.http_conversations[{index}].remote_ip", row,
                 "http_conversations.remote_ip")
    for index, row in rows("ids_alerts"):
        context = row.get("alert_context", {})
        if not isinstance(context, dict):
            raise LookupError("parse_error", "Invalid IDS alert context")
        for name in ("src_ip", "dest_ip"):
            if name in context:
                emit(context[name], f"{prefix}.ids_alerts[{index}].alert_context.{name}", row,
                     f"ids_alerts.alert_context.{name}")
