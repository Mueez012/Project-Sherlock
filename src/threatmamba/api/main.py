"""HTTP API and the live interface. Run locally: uv run uvicorn threatmamba.api.main:app --reload"""

from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from threatmamba import __version__
from threatmamba.attribution import attribute
from threatmamba.contracts import AnalyzeRequest, AnalyzeResponse
from threatmamba.ioc import RegexIOCExtractor
from threatmamba.settings import Mode, mode
from threatmamba.text import split_sentences
from threatmamba.ttp import KeywordTTPExtractor

WEB_DIR = Path(__file__).resolve().parent.parent / "web"

app = FastAPI(title="ThreatMAMBA", version=__version__)
_ioc = RegexIOCExtractor()
_ttp = KeywordTTPExtractor()


@app.get("/health")
def health() -> dict[str, str]:
    if mode() is Mode.real:
        # real mode needs trained checkpoints, which do not exist yet
        raise HTTPException(status_code=503, detail="real-model mode: checkpoints not loaded")
    return {"status": "ok", "mode": mode().value, "version": __version__}


@app.post("/api/analyze", response_model=AnalyzeResponse)
def analyze(req: AnalyzeRequest) -> AnalyzeResponse:
    sentences = split_sentences(req.text)
    return AnalyzeResponse(
        mode=mode().value,
        sentences=sentences,
        ttps=_ttp.predict(sentences),
        iocs=_ioc.extract(sentences),
        cskg=None,
        attribution=attribute(None),
    )


@app.get("/", include_in_schema=False)
def index() -> FileResponse:
    return FileResponse(WEB_DIR / "index.html")


app.mount("/static", StaticFiles(directory=WEB_DIR), name="static")
