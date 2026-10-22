"""/health, /model and the offline ATT&CK catalog."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse

from ttp_api.deps import get_catalog, get_predictor
from ttp_api.schemas import AttackCatalog, Health

router = APIRouter(tags=["meta"])


@router.get("/health", response_model=Health, responses={503: {"model": Health}},
            summary="Liveness, and whether the model is loaded")
def health(request: Request):
    state = request.app.state
    if state.predictor is not None:
        return {"status": "ok", "model_loaded": True}
    body = {"status": "error" if state.model_status == "error" else "loading", "model_loaded": False,
            "detail": state.model_error}
    return JSONResponse(body, status_code=503)


@router.get("/model", summary="Model card: version, run, label space, thresholds, validation metrics")
def model_card(predictor=Depends(get_predictor)):
    m = predictor.manifest
    return {
        "name": m.get("name"), "version": m.get("version"), "run_id": m.get("run_id"),
        "model_type": m.get("model_type"), "encoder": m.get("encoder"),
        "max_length": m.get("max_length"), "attack_version": m.get("attack_version"),
        "label_space": m.get("label_space"),
        "threshold_mode": predictor.thresholds.default_mode,
        "threshold_modes_available": sorted(predictor.thresholds.modes),
        "metrics": m.get("metrics"), "training": m.get("training"), "created_at": m.get("created_at"),
    }


@router.get("/attack/techniques", response_model=AttackCatalog,
            summary="ATT&CK v14 tactics and the techniques this model can predict")
def attack_techniques(request: Request, catalog: dict = Depends(get_catalog)):
    predictor = request.app.state.predictor
    if predictor is not None:
        ids = predictor.labels[predictor.n_tactics :]
    else:   # still loading: everything that is not a sub-technique
        ids = [t for t, v in catalog["techniques"].items() if not v["is_subtechnique"] and v["active"]]
    tactics = sorted(catalog["tactics"].values(), key=lambda t: t["order"])
    techniques = [{"id": t, "name": catalog["techniques"][t]["name"],
                   "tactic_ids": catalog["techniques"][t]["tactics"], "url": catalog["techniques"][t]["url"]}
                  for t in ids if t in catalog["techniques"]]
    return {"attack_version": catalog["attack_version"], "tactics": tactics, "techniques": techniques}
