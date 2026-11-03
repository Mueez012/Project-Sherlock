"""Figure 3 type connections. Lookup direction is independent of graph direction."""
from dataclasses import dataclass

@dataclass(frozen=True)
class OntologyEdge:
    left: str
    right: str
    label: str
    category: str = "ioc"

EDGES = tuple(OntologyEdge(*row) for row in [
    ("domain", "url", "own"), ("domain", "ip", "DNS-parse"), ("domain", "email", "own"),
    ("url", "filename", "parse/own"), ("url", "url", "connect"),
    ("filename", "registry", "use"),
    ("ip", "geo_location", "WHOIS"), ("ip", "mac", "blinded"), ("ip", "ip", "connect"),
    ("mac", "geo_location", "locate"), ("email", "account", "blinded"), ("email", "email", "connect"),
    ("command_api", "filename", "scan/UCED"), ("command_api", "cve", "scan/use"),
    ("command_api", "account", "UCED"), ("command_api", "registry", "use"),
    ("command_api", "fingerprint", "scan/UCED/blinded"),
    ("command_api", "protocol", "use/create/edit"), ("command_api", "port", "sended/received/listen"),
    ("command_api", "ip", "sended/received/listen"), ("command_api", "command_api", "invoke/next"),
    ("header", "ip", "source/target"), ("header", "port", "source/target"),
    ("header", "account", "cookies"), ("header", "time", "sended/received/spend", "temporal"),
    ("cve", "time", "published", "temporal"), ("protocol", "port", "use"),
    ("protocol", "protocol", "encapsulated"), ("time", "time", "next", "temporal"),
    ("tactic", "technique", "own", "ttp"), ("tactic", "tactic", "invoke/next", "ttp"),
    ("technique", "technique", "invoke/next", "ttp"),
    ("technique", "url", "scan/UCED", "ttp"), ("technique", "filename", "scan/UCED", "ttp"),
    ("technique", "cve", "scan/use", "ttp"), ("technique", "email", "connect", "ttp"),
    ("technique", "command_api", "UCED", "ttp"), ("technique", "registry", "scan/UCED", "ttp"),
    ("technique", "fingerprint", "UCED", "ttp"), ("technique", "protocol", "use/create/edit", "ttp"),
])
ALIASES = {"ipv4": "ip", "ipv6": "ip", "md5": "fingerprint", "sha1": "fingerprint", "sha256": "fingerprint", "path": "url"}

def family(kind: str) -> str:
    return ALIASES.get(kind, kind)

def relationship(left: str, right: str) -> OntologyEdge | None:
    pair = frozenset((family(left), family(right)))
    return next((edge for edge in EDGES if frozenset((edge.left, edge.right)) == pair), None)

def allows_ioc_edge(left: str, right: str) -> bool:
    edge = relationship(left, right)
    return edge is not None and edge.category == "ioc"
