"""Reusable report extraction. No console I/O, network calls or graph state.

Sentences are cut by ioc_hunter.text, a byte-identical copy of the hub's splitter (src/threatmamba/text.py), so a
report is cut into exactly the same units here and in the hub.
"""
from dataclasses import dataclass
from ipaddress import ip_address
import re
from ..models import IOC
from ..text import attach, segment

IOC_TYPES = {
    "domains": "domain", "ipv4s": "ipv4", "ipv6s": "ipv6",
    "urls": "url", "md5s": "md5", "sha1s": "sha1", "sha256s": "sha256",
}


REFERENCE_TITLES = (
    r"references?|sources|bibliography|further reading|additional reading|"
    r"related (?:articles|reports|content)|external links"
)
TECHNICAL_TITLES = (
    r"(?:indicators? of compromise(?:\s*\(iocs?\))?|iocs?|"
    r"(?:network|host|file) indicators|technical (?:analysis|details)|"
    r"malware analysis|command[ -]and[ -]control|conclusions?|"
    r"(?:file )?hashes|(?:malicious |c2 )?(?:domains|ip addresses|urls))"
)


def create_sentencizer():
    """Kept for existing callers. The shared splitter needs no model, so there is nothing to create."""
    return None

def heading_text(line: str) -> str:
    """Recognize explicit headings, including simple Markdown and numbering."""
    text = line.strip().strip("#* ")
    return re.sub(r"^(?:\d+(?:\.\d+)*[.)]?|[IVX]+[.)])\s+", "", text)

def filter_report_sections(report: str) -> tuple[str, list[dict]]:
    """Exclude labelled reference/navigation sections before sentence splitting.

    Keep original retained text. Resume at explicit technical/IOC headings so an
    appendix following references is not lost. Unlabelled inline citations are
    deliberately retained: a publisher hostname alone is not grounds to drop an IOC.
    """
    lines = report.splitlines(keepends=True)
    kept = []
    excluded = []
    active = None
    for index, line in enumerate(lines):
        title = heading_text(line)
        reference = bool(re.fullmatch(rf"(?:{REFERENCE_TITLES})\s*:?", title, re.I))
        reference |= bool(re.match(rf"^(?:{REFERENCE_TITLES})\s*:\s*\S", title, re.I))
        # Some dataset tables repeat 'References <citation>' on successive lines.
        # Require repeated labels rather than treating 'References to ...' as a heading.
        prefix = re.match(r"^(References|Sources)\s+\S", title, re.I)
        if prefix and not reference:
            neighbors = lines[max(0, index - 2):index] + lines[index + 1:index + 3]
            reference = any(re.match(rf"^{prefix[1]}\s+\S", heading_text(other), re.I)
                            for other in neighbors)
        resume = bool(re.fullmatch(
            rf"(?:Appendix(?:\s+[A-Z0-9]+)?\s*[:.\-]?\s*)?{TECHNICAL_TITLES}\s*:?",
            title, re.I,
        ))
        # Also respect explicit Markdown section boundaries after a bibliography.
        resume |= bool(re.match(r"^\s*#{1,6}\s+\S", line)) and not reference
        if active is not None and resume and not reference:
            excluded.append(active)
            active = None
        if reference and active is None:
            active = {"heading": title, "start_line": index + 1,
                      "end_line": index + 1, "text": ""}
        if active is not None:
            active["end_line"] = index + 1
            active["text"] += line
            kept.append("\n")
        else:
            kept.append(line)
    if active is not None:
        excluded.append(active)
    return "".join(kept), excluded

def is_indicator_list_line(line: str) -> bool:
    """Separate bare indicators/table rows while retaining soft-wrapped prose."""
    value = re.sub(r"^\s*(?:[-*\u2022]\s+|\d+[.)]\s+)", "", line).strip()
    token = r"(?:[\w-]+(?:(?:\.|\[\.\]|\(\.\))[\w-]+)+|[a-fA-F0-9]{32,64}|[a-fA-F0-9:]*:[a-fA-F0-9:]+)"
    return bool(re.fullmatch(rf"{token}(?:\s+\([^\n]*\))?[,;]?", value)
                or re.fullmatch(r"(?:TOR:)?h(?:tt|xx)ps?://\S+", value, re.I))

def split_sentences(report: str, nlp=None) -> list[str]:
    """Every unit of the report in order (sentences, headings, indicator lines), cut by the hub's splitter.

    IOCs are found in every unit; only units of kind "sentence" form the hub's timeline. `nlp` is ignored.
    """
    return [unit.text for unit in segment(report)]


def passage_contexts(report: str) -> list[str]:
    """For each unit, the passage an IOC found in it takes as context (paper III-A1): the unit itself if it is a
    sentence, otherwise the nearest sentence before it, as the hub attaches it to the timeline."""
    units = segment(report)
    sentences = [unit.text for unit in units if unit.kind == "sentence"]
    return [unit.text if number is None else sentences[number] for unit, number in zip(units, attach(units))]


def is_software_version(value: str, sentence: str) -> bool:
    """Suppress an IPv4-shaped value only when every occurrence is a version.

    Use local evidence, not the presence of 'version' anywhere in the sentence.
    An explicitly labelled IP, defanged address, or ambiguous number is retained.
    """
    occurrences = list(re.finditer(rf"(?<![\d.]){re.escape(value)}(?!\d|\.\d)", sentence))
    if not occurrences:
        return False
    for occurrence in occurrences:
        before = sentence[max(0, occurrence.start() - 70):occurrence.start()]
        after = sentence[occurrence.end():occurrence.end() + 50]
        if re.search(r"(?:ip(?: address)?|server|host)\s*[:=]?\s*$", before, re.I):
            return False
        labelled = re.search(
            r"(?:\bversion|\bver\.?|\bbuild|\bv|\bFlash Player(?: ActiveX)?)\s*[:=]?\s*$",
            before, re.I,
        )
        qualified = re.match(r"\s+(?:and|or)\s+(?:earlier|later|older|newer)\s+versions?\b", after, re.I)
        if not (labelled or qualified):
            return False
    return True

def canonical_value(kind: str, value: str) -> str:
    if kind in {"domain", "md5", "sha1", "sha256"}:
        return value.lower().rstrip(".") if kind == "domain" else value.lower()
    if kind in {"ipv4", "ipv6"}:
        return str(ip_address(value))
    if kind in {"email", "cve"}:
        from ..models import normalize
        return normalize(kind, value)
    if kind == "url":
        # A URL at the end of a sentence picks up its full stop or comma ("from hxxp://x[.]net/a.bin.").
        return value.rstrip(".,;:")
    # Preserve URL path/query case. IOCFinder handles defanging.
    return value

def find_sentence_iocs(sentences: list[str], *, extended: bool = False) -> list[list[tuple[str, str]]]:
    """Return one list of (type, value) pairs for each input sentence."""
    from ioc_finder import find_iocs

    results = []
    for sentence in sentences:
        parsed = find_iocs(sentence)
        matches = set()
        types = {**IOC_TYPES, **({"email_addresses": "email", "cves": "cve"} if extended else {})}
        for key, kind in types.items():
            for value in parsed.get(key, []):
                if kind == "ipv4" and is_software_version(value, sentence):
                    continue
                matches.add((kind, canonical_value(kind, value)))
        results.append(sorted(matches))
    return results

def build_iocs(sentences: list[str], matches: list[list[tuple[str, str]]], source: str,
               contexts: list[str] | None = None) -> list[IOC]:
    """Merge repeated IOCs within this report and append their context: the matching unit, or contexts[i] for
    unit i when given (see passage_contexts)."""
    contexts = sentences if contexts is None else contexts
    if not len(sentences) == len(matches) == len(contexts):
        raise ValueError("Each sentence must have a corresponding match list.")
    objects: dict[tuple[str, str], IOC] = {}
    for context, sentence_matches in zip(contexts, matches):
        for kind, value in dict.fromkeys(sentence_matches):
            key = (kind, value)
            if key not in objects:
                objects[key] = IOC(value=value, type=kind, source=source)
            if context not in objects[key].context:
                objects[key].context.append(context)
    return list(objects.values())

@dataclass
class ExtractionResult:
    source: str
    original_text: str
    retained_text: str
    excluded_sections: list[dict]
    sentences: list[str]
    matches: list[list[tuple[str, str]]]
    iocs: list[IOC]


def extract_report(report: str, *, source: str = "cti report", nlp=None,
                   include_references: bool = False,
                   extended_types: bool = False) -> ExtractionResult:
    """Run the same extraction stages used by interactive review, without prompts.

    `nlp` is ignored (kept for existing callers). Empty text returns an empty
    result; invalid non-string input raises ValueError.
    """
    if not isinstance(report, str):
        raise ValueError("Report must be text")
    body, excluded = (report, []) if include_references else filter_report_sections(report)
    sentences = split_sentences(body)
    matches = find_sentence_iocs(sentences, extended=extended_types)
    return ExtractionResult(source, report, body, excluded, sentences, matches,
                            build_iocs(sentences, matches, source, passage_contexts(body)))
