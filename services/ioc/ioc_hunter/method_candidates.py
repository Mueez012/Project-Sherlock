"""Research candidates derived from Table I and strict ontology membership.

These are not confirmed provider capabilities and must never be auto-scheduled.
"""
from .method_spec import MethodSpec
from .ontology import allows_ioc_edge

SOURCE_TYPES = {
    "rapiddns": ("domain", "ipv4", "ipv6", "url", "time"),
    "alienvault": ("ipv4", "domain", "url", "geo_location", "email", "md5", "sha1", "sha256", "port", "protocol"),
    "virustotal": ("url", "md5", "sha1", "sha256", "domain", "ipv4", "geo_location", "filename", "port", "cve", "command_api", "registry"),
}


def candidate_methods() -> dict[str, MethodSpec]:
    return {
        f"{source}.{left}_to_{right}": MethodSpec(
            id=f"{source}.{left}_to_{right}", input_type=left,
            output_type=right, source=source)
        for source, types in SOURCE_TYPES.items()
        for left in types for right in types if allows_ioc_edge(left, right)
    }
