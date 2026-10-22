"""ATT&CK v14 catalog (offline): ids -> names, tactics, kill-chain order, URLs.

Built once from the official MITRE STIX bundle (data/attack/enterprise-attack-v14.json,
from github.com/mitre/cti, tag ATT&CK-v14.1) into a small JSON file the API loads
at start-up:

  python -m ttp_api.attack_catalog          # writes data/attack/catalog-v14.json
"""
from __future__ import annotations

import argparse
import json
from functools import lru_cache
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BUNDLE = ROOT / "data" / "attack" / "enterprise-attack-v14.json"
CATALOG = ROOT / "data" / "attack" / "catalog-v14.json"


def _external_id(obj: dict) -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


def _url(obj: dict) -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("url")
    return None


def build_catalog(bundle_path: Path = BUNDLE) -> dict:
    bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
    objects = bundle["objects"]
    by_ref = {o["id"]: o for o in objects}
    matrix = next(o for o in objects if o["type"] == "x-mitre-matrix")
    tactics, shortname_to_id = {}, {}
    for order, ref in enumerate(matrix["tactic_refs"], start=1):
        obj = by_ref[ref]
        tid = _external_id(obj)
        shortname_to_id[obj["x_mitre_shortname"]] = tid
        tactics[tid] = {"id": tid, "name": obj["name"], "shortname": obj["x_mitre_shortname"],
                        "order": order, "url": _url(obj)}
    techniques = {}
    for obj in objects:
        if obj["type"] != "attack-pattern":
            continue
        tid = _external_id(obj)
        if not tid:
            continue
        active = not obj.get("revoked", False) and not obj.get("x_mitre_deprecated", False)
        if tid in techniques and techniques[tid]["active"] and not active:
            continue       # keep the live object if a revoked twin exists
        phases = [p["phase_name"] for p in obj.get("kill_chain_phases", [])
                  if p.get("kill_chain_name") == "mitre-attack"]
        techniques[tid] = {
            "id": tid, "name": obj["name"], "url": _url(obj), "active": active,
            "is_subtechnique": bool(obj.get("x_mitre_is_subtechnique", False)),
            "tactics": sorted((shortname_to_id[p] for p in phases if p in shortname_to_id),
                              key=lambda t: tactics[t]["order"]),
        }
    version = matrix.get("x_mitre_version") or "14"
    return {"attack_version": "14.1", "matrix_version": version, "source": "mitre/cti ATT&CK-v14.1",
            "tactics": tactics, "techniques": techniques}


@lru_cache(maxsize=4)
def load_catalog(path: str = str(CATALOG)) -> dict:
    p = Path(path)
    if not p.exists():
        catalog = build_catalog()
        p.write_text(json.dumps(catalog, indent=1, ensure_ascii=False), encoding="utf-8")
        return catalog
    return json.loads(p.read_text(encoding="utf-8"))


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--bundle", type=Path, default=BUNDLE)
    p.add_argument("--out", type=Path, default=CATALOG)
    args = p.parse_args()
    catalog = build_catalog(args.bundle)
    args.out.write_text(json.dumps(catalog, indent=1, ensure_ascii=False), encoding="utf-8")
    print(f"{len(catalog['tactics'])} tactics, {len(catalog['techniques'])} techniques -> {args.out}")


if __name__ == "__main__":
    main()
