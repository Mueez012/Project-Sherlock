"""Client for the TTP service (services/ttp). It satisfies the TTPExtractor protocol, so the hub uses it exactly
like the keyword stub.

    POST {TM_TTP_URL}/api/v1/predict
    request   {"sentences": [{"index": 0, "text": "..."}, ...]}
    response  {"sentences": [{"index": 0, "labels": [{"id": "T1566", "p": 0.93, "passed": true}, ...]}, ...], ...}

Every label the service marks as passed becomes one TTPHit: techniques (T####) and tactics (TA####) alike.
Extra fields in the response (model name, thresholds, ...) are ignored.
"""

import httpx
from pydantic import BaseModel, ValidationError

from threatmamba.clients.errors import ServiceError
from threatmamba.contracts import TTPHit

PREDICT_PATH = "/api/v1/predict"
HEALTH_PATH = "/api/v1/health"


class _Label(BaseModel):
    id: str
    p: float
    passed: bool


class _Sentence(BaseModel):
    index: int
    labels: list[_Label]


class _PredictResponse(BaseModel):
    sentences: list[_Sentence]


class TTPServiceExtractor:
    def __init__(self, base_url: str, timeout_s: float = 600.0, transport: httpx.BaseTransport | None = None) -> None:
        self._base_url = base_url.rstrip("/")
        self._timeout_s = timeout_s
        self._transport = transport  # tests pass httpx.MockTransport; production uses the network

    def _client(self, timeout_s: float) -> httpx.Client:
        return httpx.Client(base_url=self._base_url, timeout=timeout_s, transport=self._transport)

    def predict(self, sentences: list[str]) -> list[TTPHit]:
        payload = {"sentences": [{"index": i, "text": s} for i, s in enumerate(sentences)]}
        try:
            with self._client(self._timeout_s) as client:
                response = client.post(PREDICT_PATH, json=payload)
                response.raise_for_status()
            body = _PredictResponse.model_validate_json(response.content)
            hits: list[TTPHit] = []
            for sentence in body.sentences:
                if not 0 <= sentence.index < len(sentences):
                    raise ServiceError("ttp", f"answer refers to sentence {sentence.index}, only {len(sentences)} sent")
                for label in sentence.labels:
                    if label.passed:
                        hits.append(TTPHit(technique_id=label.id, score=label.p, sentence_index=sentence.index))
        except httpx.HTTPError as e:
            raise ServiceError("ttp", f"{type(e).__name__}: {e}") from e
        except ValidationError as e:
            raise ServiceError("ttp", f"malformed answer: {e.errors()[0]['msg']}") from e
        return hits

    def health(self) -> str:
        """'ok' when the service answers its health check with 200, otherwise 'down'."""
        try:
            with self._client(5.0) as client:
                return "ok" if client.get(HEALTH_PATH).status_code == 200 else "down"
        except httpx.HTTPError:
            return "down"
