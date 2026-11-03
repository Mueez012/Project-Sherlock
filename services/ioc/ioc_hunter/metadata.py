"""Typed metadata extraction without inferred relationships.

These outputs alone never authorize an edge. A provider must still supply a
relationship parser and the standalone validator must support that relation.
"""
import json
from .models import IOC, normalize

FIELD_TYPES = {"email": "email", "filename": "filename", "cve": "cve",
               "country_code": "geo_location", "port": "port", "protocol": "protocol"}

def extract_metadata(fields: dict, *, source: str) -> list[IOC]:
    """Accept explicitly named provider fields; ignore unrelated numbers/text."""
    outputs = {}
    for field, kind in FIELD_TYPES.items():
        if field not in fields or fields[field] is None:
            continue
        values = fields[field] if isinstance(fields[field], list) else [fields[field]]
        for raw in values:
            if isinstance(raw, bool) or not isinstance(raw, (str, int)):
                continue
            try:
                value = normalize(kind, str(raw))
            except ValueError:
                continue
            outputs[(kind, value)] = IOC(value, kind, [json.dumps({field: raw}, ensure_ascii=False)], source)
    return list(outputs.values())
