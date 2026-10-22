"""POST /api/v1/predict: the hub's call. Sentences in (split and numbered by the hub), labels out.

The answer keeps the hub's index numbers, never re-splits or renumbers, and lists for each
sentence every label that passed this bundle's per-sentence thresholds (its default mode),
tactics included, plus labels above LABEL_FLOOR with passed=false. Field names are single
words, so the plain dict is returned as is (no camelCase response model).
"""
from __future__ import annotations

import asyncio

import numpy as np
from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from ttp_api.deps import get_predictor

router = APIRouter(tags=["hub"])

LABEL_FLOOR = 0.05  # labels below this probability (and not passed) are left out to keep the answer small
MAX_SENTENCES = 20_000  # the hub accepts reports of up to 20,000 sentences and sends them in one call


class SentenceIn(BaseModel):
    index: int = Field(ge=0)
    text: str


class PredictRequest(BaseModel):
    sentences: list[SentenceIn] = Field(max_length=MAX_SENTENCES)


@router.post("/predict", summary="Labels for each sentence the hub sends (used by the hub)")
async def predict(req: PredictRequest, predictor=Depends(get_predictor)) -> dict:
    texts = [s.text for s in req.sentences]
    # (N, 203) probabilities, columns in the bundle's label order; TTPPredictor.predict holds its own lock.
    probs = await asyncio.to_thread(predictor.predict, texts) if texts else np.zeros((0, len(predictor.labels)))
    labels = predictor.labels
    thresholds = predictor.thresholds.get(n_labels=len(labels))  # per-sentence thresholds, default mode
    sentences = []
    for s, row in zip(req.sentences, probs):
        keep = np.flatnonzero((row >= thresholds) | (row >= LABEL_FLOOR))
        sentences.append({"index": s.index, "labels": [
            {"id": labels[j], "p": round(float(row[j]), 4), "passed": bool(row[j] >= thresholds[j])}
            for j in keep[np.argsort(-row[keep], kind="stable")]
        ]})
    return {"model": {"bundle": predictor.manifest.get("version")}, "sentences": sentences}
