"""FastAPI app for TTP extraction (Sherlock backend).

Run (from Implementation/):
  uvicorn ttp_api.main:app --port 8001            # docs at http://127.0.0.1:8001/docs

The model loads once, in a background thread, when the server starts;
/api/v1/health answers 503 until it is ready (about 30 s on CPU).
"""
from __future__ import annotations

import logging
import threading
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from ttp_api import errors
from ttp_api.attack_catalog import load_catalog
from ttp_api.config import Settings
from ttp_api.jobs import InMemoryJobStore, JobRunner, SQLiteJobStore
from ttp_api.routes import analyses, meta, predict

log = logging.getLogger("ttp_api")
DESCRIPTION = """
Upload a CTI report and get the MITRE ATT&CK tactics and techniques it describes,
each with a confidence score and the sentences that triggered it.

**Flow:** `POST /analyses` (202 + job id) → poll `GET /analyses/{id}` → `GET /analyses/{id}/result`
→ optional `GET /analyses/{id}/export?format=json|csv|navigator|stix`.

**Hub:** `POST /predict` takes sentences already split and numbered by the hub and returns, per
sentence, every label that passed (tactics and techniques), keeping the hub's index numbers.

Errors use `application/problem+json` (RFC 9457) with a machine-readable `code`.
Confidence bands: high ≥ 0.80, medium 0.50–0.79, low = passed its threshold but < 0.50.
"""


def _load_predictor(app: FastAPI, settings: Settings) -> None:
    from ttp_extraction.inference.predictor import TTPPredictor

    try:
        app.state.predictor = TTPPredictor.load(settings.bundle_dir, device=settings.device,
                                                num_threads=settings.torch_threads)
        app.state.model_status = "ready"
    except Exception as exc:     # keep serving /health with the reason
        log.exception("model failed to load")
        app.state.model_status, app.state.model_error = "error", f"{exc.__class__.__name__}: {exc}"


def create_app(settings: Settings | None = None, predictor=None) -> FastAPI:
    settings = settings or Settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        app.state.settings = settings
        app.state.catalog = load_catalog(str(settings.catalog_path))
        app.state.store = (SQLiteJobStore(settings.sqlite_path, settings.keep_jobs)
                           if settings.job_store == "sqlite" else InMemoryJobStore(settings.keep_jobs))
        app.state.runner = JobRunner(app.state.store)
        app.state.predictor, app.state.model_status, app.state.model_error = predictor, "loading", None
        if predictor is not None:
            app.state.model_status = "ready"
        elif settings.load_model:
            threading.Thread(target=_load_predictor, args=(app, settings), daemon=True,
                             name="model-loader").start()
        yield
        app.state.runner.shutdown()

    app = FastAPI(title="Sherlock: TTP extraction API", version="1.0.0",
                  description=DESCRIPTION, lifespan=lifespan,
                  docs_url="/docs", openapi_url="/openapi.json")
    app.add_middleware(CORSMiddleware, allow_origins=settings.cors_origins, allow_credentials=False,
                       allow_methods=["GET", "POST", "DELETE"], allow_headers=["*"])
    errors.install(app)
    app.include_router(meta.router, prefix="/api/v1")
    app.include_router(analyses.router, prefix="/api/v1")
    app.include_router(predict.router, prefix="/api/v1")    # the hub's call
    return app


logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
app = create_app()
