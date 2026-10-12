"""Baseline TTP extractor used in stub mode: keyword rules, no model. Replaced by the trained extractor."""

import re

from threatmamba.contracts import TTPHit

_RULES: dict[str, list[str]] = {
    "T1566": [r"phishing", r"spear-?phish", r"malicious attachment"],
    "T1059": [r"powershell", r"cmd\.exe", r"command[- ]line", r"script interpreter"],
    "T1071": [r"\bhttps? traffic\b", r"command[- ]and[- ]control", r"\bc2\b"],
    "T1105": [r"download(?:ed|s)? (?:a |an |the )?(?:payload|tool|file)"],
    "T1547": [r"run key", r"startup folder", r"autostart"],
    "T1053": [r"scheduled task", r"schtasks", r"cron job"],
    "T1027": [r"obfuscat", r"encod(?:ed|ing) payload", r"packed"],
    "T1003": [r"mimikatz", r"credential dump", r"lsass"],
    "T1190": [r"exploit(?:ed|s)? (?:a |the )?(?:public|web|vulnerab)", r"cve-\d{4}-\d+"],
    "T1204": [r"user execution", r"(?:victim|user) (?:opens|clicks|enabled? macros)"],
    "T1041": [r"exfiltrat"],
    "T1486": [r"ransomware", r"encrypt(?:ed|s) (?:files|data)"],
}
_COMPILED = {tid: [re.compile(p, re.IGNORECASE) for p in pats] for tid, pats in _RULES.items()}


class KeywordTTPExtractor:
    def predict(self, sentences: list[str]) -> list[TTPHit]:
        hits: list[TTPHit] = []
        for i, sentence in enumerate(sentences):
            for tid, patterns in _COMPILED.items():
                n = sum(bool(p.search(sentence)) for p in patterns)
                if n:
                    hits.append(TTPHit(technique_id=tid, score=min(1.0, 0.5 + 0.25 * n), sentence_index=i))
        return hits
