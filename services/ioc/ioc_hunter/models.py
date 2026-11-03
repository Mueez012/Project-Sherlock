"""Shared observable identities; no graph or algorithm state."""
from __future__ import annotations
from dataclasses import dataclass, field
from ipaddress import ip_address
import re
from urllib.parse import urlsplit, urlunsplit

@dataclass
class IOC:
    value: str
    type: str
    context: list[str] = field(default_factory=list)
    source: str = ""

HASH_LENGTHS = {"md5": 32, "sha1": 40, "sha256": 64}

def normalize(kind: str, value: str) -> str:
    """Validate structured provider fields without changing URL path/query case."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError("An IOC value must be a nonempty string")
    value = value.strip()
    if kind in {"ipv4", "ipv6"}:
        address = ip_address(value)
        if address.version != int(kind[-1]):
            raise ValueError("IP version does not match IOC type")
        return str(address)
    if kind == "domain":
        value = value.rstrip(".").encode("idna").decode("ascii").lower()
        try:
            ip_address(value)
        except ValueError:
            pass
        else:
            raise ValueError("IP address is not a domain")
        if len(value) > 253 or "." not in value or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", p) for p in value.split(".")):
            raise ValueError("Invalid domain")
        return value
    if kind in HASH_LENGTHS:
        if not re.fullmatch(r"[0-9a-fA-F]{" + str(HASH_LENGTHS[kind]) + "}", value):
            raise ValueError("Invalid hash")
        return value.lower()
    if kind == "url":
        parts = urlsplit(value)
        if parts.scheme.lower() not in {"http", "https", "ftp"} or not parts.hostname or re.search(r"\s", value):
            raise ValueError("Invalid URL")
        if parts.username is not None or parts.password is not None:
            raise ValueError("Credential-bearing URLs are not supported")
        host = parts.hostname
        try:
            addr = ip_address(host)
            host = "[" + str(addr) + "]" if addr.version == 6 else str(addr)
        except ValueError:
            host = normalize("domain", host)
        port = parts.port
        netloc = host + (":" + str(port) if port is not None else "")
        return urlunsplit((parts.scheme.lower(), netloc, parts.path, parts.query, parts.fragment))
    if kind == "email":
        local, sep, host = value.rpartition("@")
        if not sep or not local or re.search(r"[\s<>]", local):
            raise ValueError("Invalid email")
        return local.lower() + "@" + normalize("domain", host)
    if kind == "cve":
        if not re.fullmatch(r"CVE-\d{4}-\d{4,}", value, re.I):
            raise ValueError("Invalid CVE")
        return value.upper()
    if kind == "port":
        if not value.isdigit() or not 0 <= int(value) <= 65535:
            raise ValueError("Invalid port")
        return str(int(value))
    if kind == "protocol":
        if value.lower() not in {"tcp", "udp", "icmp", "icmpv6", "http", "https", "ftp", "smtp", "dns", "tls", "ssh"}:
            raise ValueError("Unsupported protocol")
        return value.lower()
    if kind == "geo_location":
        if not re.fullmatch(r"[A-Za-z]{2}", value):
            raise ValueError("Geolocation currently uses country codes")
        return value.upper()
    if kind == "filename":
        if value in {".", ".."} or re.search(r"[\/\\\x00-\x1f]", value):
            raise ValueError("Expected a basename")
        return value
    if kind in {"registry", "command_api", "account", "header", "fingerprint", "path", "time", "technique", "tactic", "mac"}:
        return value
    raise ValueError("Unsupported IOC type: " + kind)

def identity(ioc: IOC) -> tuple[str, str]:
    return ioc.type, normalize(ioc.type, ioc.value)
