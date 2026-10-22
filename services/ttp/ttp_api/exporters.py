"""Export a finished AnalysisResult as JSON, CSV, an ATT&CK Navigator layer or a STIX 2.1 bundle."""
from __future__ import annotations

import csv
import io
import json
import re
import uuid
from datetime import datetime, timezone

NAMESPACE = uuid.UUID("6f0b1c2e-8f3a-4d1e-9b7a-5c2d3e4f5a6b")     # fixed: same input -> same STIX ids


def _slug(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9_-]+", "_", name).strip("_")[:60] or "analysis"


def filename(result: dict, fmt: str) -> str:
    ext = {"json": "json", "csv": "csv", "navigator": "layer.json", "stix": "stix.json"}[fmt]
    return f"{_slug(result['incident_name'])}_{result['id']}.{ext}"


def to_json(result: dict) -> str:
    return json.dumps(result, indent=2, ensure_ascii=False)


def to_csv(result: dict) -> str:
    tactic_names = {t["id"]: t["name"] for t in result["tactics"]}
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(["technique_id", "technique_name", "tactics", "confidence", "band",
                     "mean_confidence", "sentence_count", "threshold", "top_evidence", "url"])
    for t in result["techniques"]:
        tactics = "; ".join(f"{tid} {tactic_names.get(tid, '')}".strip() for tid in t["tactic_ids"])
        top = t["evidence"][0]["text"] if t["evidence"] else ""
        writer.writerow([t["id"], t["name"], tactics, f"{t['confidence']:.4f}", t["band"],
                         f"{t['mean_confidence']:.4f}", t["sentence_count"], f"{t['threshold']:.4f}",
                         top, t["url"]])
    return out.getvalue()


def to_navigator(result: dict, catalog: dict) -> dict:
    """ATT&CK Navigator layer, format 4.5, enterprise-attack v14.

    Open it at https://mitre-attack.github.io/attack-navigator/ ("Open Existing Layer").
    score = confidence x 100; comment = the strongest evidence sentence.
    """
    shortnames = {tid: t.get("shortname") for tid, t in catalog.get("tactics", {}).items()}
    techniques = []
    for t in result["techniques"]:
        comment = t["evidence"][0]["text"] if t["evidence"] else ""
        for tactic_id in t["tactic_ids"] or [None]:
            entry = {"techniqueID": t["id"], "score": round(100 * t["confidence"]), "color": "",
                     "comment": comment[:500], "enabled": True, "showSubtechniques": False,
                     "metadata": [{"name": "sentences", "value": str(t["sentence_count"])},
                                  {"name": "band", "value": t["band"]}]}
            if tactic_id and shortnames.get(tactic_id):
                entry["tactic"] = shortnames[tactic_id]
            techniques.append(entry)
    return {
        "name": f"{result['incident_name']} (Sherlock)"[:100],
        "versions": {"attack": "14", "navigator": "4.9.1", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": (f"TTPs extracted by {result['model']['name']} {result['model']['version']} "
                        f"from {result['document'].get('filename') or 'pasted text'}. "
                        "Scores are model confidence x 100, not verified findings."),
        "sorting": 3,
        "layout": {"layout": "side", "aggregateFunction": "max", "showID": True, "showName": True},
        "hideDisabled": False,
        "techniques": techniques,
        "gradient": {"colors": ["#dbe7ff", "#5b9bff", "#1f5fd1"], "minValue": 0, "maxValue": 100},
        "legendItems": [],
        "metadata": [{"name": "analysis_id", "value": result["id"]},
                     {"name": "sha256", "value": result["document"]["sha256"]}],
        "showTacticRowBackground": False,
        "selectTechniquesAcrossTactics": True,
        "selectSubtechniquesWithParent": False,
    }


def _stix_time(value: str | None = None) -> str:
    dt = datetime.fromisoformat(value) if value else datetime.now(timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def to_stix(result: dict) -> dict:
    """STIX 2.1 bundle: identity (producer), one attack-pattern per technique, and a report.

    attack-pattern objects carry the ATT&CK id in external_references, the usual
    way tools link to ATT&CK. Ids are uuid5 from the analysis id, so exporting
    the same result twice gives the same bundle.
    """
    created = _stix_time(result["completed_at"])
    key = result["id"]
    identity_id = f"identity--{uuid.uuid5(NAMESPACE, 'sherklock-honed')}"
    objects: list[dict] = [{
        "type": "identity", "spec_version": "2.1", "id": identity_id, "created": created,
        "modified": created, "name": "Sherlock (ThreatMAMBA-TTP)", "identity_class": "system",
    }]
    refs = []
    for t in result["techniques"]:
        ap_id = f"attack-pattern--{uuid.uuid5(NAMESPACE, key + t['id'])}"
        refs.append(ap_id)
        objects.append({
            "type": "attack-pattern", "spec_version": "2.1", "id": ap_id, "created": created,
            "modified": created, "created_by_ref": identity_id, "name": t["name"],
            "confidence": round(100 * t["confidence"]),
            "external_references": [{"source_name": "mitre-attack", "external_id": t["id"], "url": t["url"]}],
            "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": p}
                                  for p in t.get("tactic_shortnames", [])],
        })
        if not objects[-1]["kill_chain_phases"]:
            del objects[-1]["kill_chain_phases"]
    report = {
        "type": "report", "spec_version": "2.1", "id": f"report--{uuid.uuid5(NAMESPACE, key)}",
        "created": created, "modified": created, "created_by_ref": identity_id,
        "name": result["incident_name"], "report_types": ["threat-report"], "published": created,
        "description": (f"ATT&CK techniques extracted automatically by {result['model']['name']} "
                        f"{result['model']['version']} (confidence = model probability x 100)."),
        "object_refs": refs or [identity_id],
        "external_references": [{"source_name": "sherklock-analysis", "external_id": key}],
    }
    objects.append(report)
    return {"type": "bundle", "id": f"bundle--{uuid.uuid5(NAMESPACE, key + 'bundle')}", "objects": objects}


def export(result: dict, fmt: str, catalog: dict) -> tuple[str, str]:
    """(body, media type)."""
    if fmt == "json":
        return to_json(result), "application/json"
    if fmt == "csv":
        return to_csv(result), "text/csv; charset=utf-8"
    if fmt == "navigator":
        return json.dumps(to_navigator(result, catalog), indent=2, ensure_ascii=False), "application/json"
    if fmt == "stix":
        shortnames = {tid: t.get("shortname") for tid, t in catalog.get("tactics", {}).items()}
        enriched = {**result, "techniques": [
            {**t, "tactic_shortnames": [shortnames[x] for x in t["tactic_ids"] if shortnames.get(x)]}
            for t in result["techniques"]]}
        return json.dumps(to_stix(enriched), indent=2, ensure_ascii=False), "application/stix+json;version=2.1"
    raise ValueError(fmt)
