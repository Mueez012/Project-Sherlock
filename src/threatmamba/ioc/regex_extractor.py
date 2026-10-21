"""Baseline IOC extractor used in stub mode. The real pipeline uses IOCFinder (paper Sec. III-A1)."""

import re

from threatmamba.contracts import IOC, IOCType

_PATTERNS: list[tuple[IOCType, re.Pattern[str]]] = [
    (IOCType.url, re.compile(r"\bhxxps?://\S+|\bhttps?://\S+", re.IGNORECASE)),
    (IOCType.email, re.compile(r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b")),
    (IOCType.cve, re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)),
    (IOCType.sha256, re.compile(r"\b[a-fA-F0-9]{64}\b")),
    (IOCType.sha1, re.compile(r"\b[a-fA-F0-9]{40}\b")),
    (IOCType.md5, re.compile(r"\b[a-fA-F0-9]{32}\b")),
    (IOCType.ipv4, re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.|\[\.\])){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")),
    (IOCType.domain, re.compile(r"\b(?:[a-z0-9-]+(?:\.|\[\.\]))+(?:com|net|org|info|ru|cn|io|biz|xyz|top)\b", re.I)),
]


def _refang(value: str) -> str:
    return value.replace("[.]", ".").replace("hxxp", "http").rstrip(".,;)")


class RegexIOCExtractor:
    """Every indicator once, with every sentence it appears in (the same shape the IOC-hunter client returns)."""

    def extract(self, sentences: list[str], text: str | None = None) -> list[IOC]:
        found: dict[tuple[IOCType, str], IOC] = {}
        for i, sentence in enumerate(sentences):
            taken: list[tuple[int, int]] = []  # spans already claimed by a more specific type
            for ioc_type, pattern in _PATTERNS:
                for m in pattern.finditer(sentence):
                    if any(m.start() < e and s < m.end() for s, e in taken):
                        continue
                    taken.append((m.start(), m.end()))
                    value = _refang(m.group(0))
                    if ioc_type is IOCType.cve:
                        value = value.upper()
                    key = (ioc_type, value.lower())
                    ioc = found.setdefault(key, IOC(type=ioc_type, value=value, source="regex stub"))
                    if i not in ioc.sentence_indices:
                        ioc.sentence_indices.append(i)
                        ioc.context.append(sentence)
        return list(found.values())
