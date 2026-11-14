"""Positions in supplied report sentences; no sentence segmentation or hashing."""
from __future__ import annotations

import re

from ..models import normalize


def sentence_positions(text: str, sentences: list[str], *, report_id=None,
                       excluded_sections=()) -> list[dict]:
    """Align each saved sentence after its predecessor in the original text."""
    line_offsets, offset = [0], 0
    for line in text.splitlines(keepends=True):
        offset += len(line)
        line_offsets.append(offset)
    excluded = []
    for section in excluded_sections:
        start = max(0, section["start_line"] - 1)
        end = min(len(line_offsets) - 1, section["end_line"])
        excluded.append((line_offsets[start], line_offsets[end]))
    result, cursor = [], 0
    for index, sentence in enumerate(sentences):
        start = text.find(sentence, cursor) if sentence else -1
        end = start + len(sentence) if start >= 0 else None
        if start >= 0:
            cursor = end
        overlaps = [(max(start, a), min(end, b)) for a, b in excluded
                    if start >= 0 and max(start, a) < min(end, b)]
        is_excluded = bool(overlaps) and sum(b - a for a, b in overlaps) == len(sentence)
        result.append({
            "id": f"{report_id}:s{index}" if report_id is not None else f"s{index}",
            "sentence_index": index, "text": sentence,
            "char_start": start if start >= 0 else None, "char_end": end,
            "position_status": "located" if start >= 0 else "unavailable",
            "excluded": is_excluded,
            "exclusion_reason": "reference_section" if is_excluded else "",
            "excluded_spans": [[a, b] for a, b in overlaps],
        })
    return result


def matching_text(sentence: dict) -> str:
    """Mask excluded source spans without changing the saved sentence or index."""
    start = sentence["char_start"]
    if start is None:
        return sentence["text"]
    chars = list(sentence["text"])
    for left, right in sentence.get("excluded_spans", []):
        chars[left - start:right - start] = " " * (right - left)
    return "".join(chars)


def _refang(value: str) -> str:
    value = value.replace("[.]", ".").replace("(.)", ".")
    value = value.replace("[:]", ":").replace("(:)", ":")
    return re.sub(r"^hxxp(s?)", r"http\1", value, flags=re.I)


def _pattern(kind: str, value: str) -> str:
    parts = []
    for char in value:
        parts.append(r"(?:\.|\[\.\]|\(\.\))" if char == "." else
                     r"(?::|\[:\]|\(:\))" if char == ":" else re.escape(char))
    pattern = "".join(parts)
    if kind == "url":
        pattern = re.sub(r"^https", "(?:https|hxxps)", pattern)
        pattern = re.sub(r"^http(?=\()", "(?:http|hxxp)", pattern)
    if kind in {"domain", "email", "ipv4", "ipv6", "md5", "sha1", "sha256", "cve"}:
        pattern = r"(?<![\w.-])" + pattern + r"(?![\w-]|\.[\w-])"
    return pattern


def locate_occurrences(sentence: dict, kind: str, value: str) -> list[dict]:
    """Return only verified spans; canonicalization is not proof of location.

    This conservative locator covers literal/refanged spellings. Other derived
    values (for example a canonicalized CIDR address) retain their sentence link
    with no invented exact span.
    """
    if sentence["char_start"] is None:
        return []
    text, output = sentence["text"], []
    try:
        expected = normalize(kind, value)
    except ValueError:
        return []
    flags = re.I if kind != "url" else 0
    # URL scheme/host may differ in case while path/query must retain theirs.
    if kind == "url":
        pattern = _pattern(kind, value)
        matches = re.finditer(pattern, text, re.I)
    else:
        matches = re.finditer(_pattern(kind, value), text, flags)
    for match in matches:
        raw = match.group()
        if kind == "domain" and text[:match.start()].endswith(("[.]", "(.)")):
            # Do not claim a suffix inside a larger defanged host as a literal.
            continue
        try:
            if normalize(kind, _refang(raw)) != expected:
                continue
        except ValueError:
            continue
        left, right = sentence["char_start"] + match.start(), sentence["char_start"] + match.end()
        if any(max(left, a) < min(right, b) for a, b in sentence.get("excluded_spans", [])):
            continue
        if kind == "ipv4" and raw == value:
            before, after = text[max(0, match.start() - 70):match.start()], text[match.end():match.end() + 50]
            labelled_version = re.search(
                r"(?:\bversion|\bver\.?|\bbuild|\bv|\bFlash Player(?: ActiveX)?)\s*[:=]?\s*$",
                before, re.I)
            qualified_version = re.match(r"\s+(?:and|or)\s+(?:earlier|later|older|newer)\s+versions?\b", after, re.I)
            if labelled_version or qualified_version:
                continue
        token_start = max(text.rfind(" ", 0, match.start()), text.rfind("\n", 0, match.start())) + 1
        token_end = re.search(r"\s", text[match.end():])
        token = text[token_start:match.end() + token_end.start()] if token_end else text[token_start:]
        component = kind == "domain" and ("@" in token or "://" in _refang(token))
        output.append({"raw_value": raw, "char_start": left, "char_end": right,
                       "location_kind": "derived_component" if component else "literal"})
    return output
