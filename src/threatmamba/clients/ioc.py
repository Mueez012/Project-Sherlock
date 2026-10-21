"""Client for the IOC service (services/ioc: IOC-hunter behind a thin HTTP door). It satisfies the IOCExtractor
protocol, so the hub uses it exactly like the regex stub.

    POST {TM_IOC_URL}/v1/extract
    request   {"text": "<the report>", "sentences": ["<hub sentence 0>", ...], "extended_types": false}
    response  IOC-hunter's extract_report() result unchanged ("iocs", "sentences", "excluded_sections", ...), plus
              "sentence_matches": one list of [type, value] pairs per hub sentence, from IOC-hunter's own matcher

IOC-hunter numbers sentences with its own splitter, so the hub cannot reuse its numbering. Instead it keeps
exactly the indicators IOC-hunter kept (its reference-section filter and software-version check stay in force)
and gives each one every hub sentence whose matches contain it, skipping hub sentences that lie inside a
section IOC-hunter excluded. IOC-hunter's values, types, context and source are passed on unchanged.
"""

import httpx
from pydantic import BaseModel, ValidationError

from threatmamba.clients.errors import ServiceError
from threatmamba.contracts import IOC

EXTRACT_PATH = "/v1/extract"
HEALTH_PATH = "/health"


class _NativeIOC(BaseModel):
    value: str
    type: str
    context: list[str] = []
    source: str = ""


class _ExcludedSection(BaseModel):
    heading: str = ""
    text: str = ""


class _ExtractResponse(BaseModel):
    iocs: list[_NativeIOC]
    excluded_sections: list[_ExcludedSection] = []
    sentence_matches: list[list[tuple[str, str]]]


class IOCServiceExtractor:
    def __init__(
        self,
        base_url: str,
        timeout_s: float = 120.0,
        transport: httpx.BaseTransport | None = None,
        *,
        extended_types: bool = False,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._timeout_s = timeout_s
        self._extended_types = extended_types  # IOC-hunter's switch for emails and CVEs
        self._transport = transport  # tests pass httpx.MockTransport; production uses the network

    def _client(self, timeout_s: float) -> httpx.Client:
        return httpx.Client(base_url=self._base_url, timeout=timeout_s, transport=self._transport)

    def extract(self, sentences: list[str], text: str | None = None) -> list[IOC]:
        # Pre-split input (a D2 report sent as sentences) has no original text; one sentence per line keeps every
        # heading on its own line, which is what IOC-hunter's section filter reads.
        payload = {
            "text": text if text is not None else "\n".join(sentences),
            "sentences": sentences,
            "extended_types": self._extended_types,
        }
        try:
            with self._client(self._timeout_s) as client:
                response = client.post(EXTRACT_PATH, json=payload)
                response.raise_for_status()
            body = _ExtractResponse.model_validate_json(response.content)
            if len(body.sentence_matches) != len(sentences):
                matched, sent = len(body.sentence_matches), len(sentences)
                raise ServiceError("ioc", f"answer matched {matched} sentences, {sent} sent")
            return self._join(sentences, body)
        except httpx.HTTPError as e:
            raise ServiceError("ioc", f"{type(e).__name__}: {e}") from e
        except ValidationError as e:
            raise ServiceError("ioc", f"malformed answer: {e.errors()[0]['msg']}") from e

    @staticmethod
    def _join(sentences: list[str], body: _ExtractResponse) -> list[IOC]:
        excluded = [s.text for s in body.excluded_sections if s.text]
        skipped = {i for i, s in enumerate(sentences) if s.strip() and any(s.strip() in text for text in excluded)}
        where: dict[tuple[str, str], list[int]] = {(i.type, i.value): [] for i in body.iocs}
        for index, pairs in enumerate(body.sentence_matches):
            if index in skipped:
                continue
            for pair in dict.fromkeys(pairs):
                if pair in where:
                    where[pair].append(index)
        return [
            IOC(
                type=i.type,
                value=i.value,
                sentence_indices=where[(i.type, i.value)],
                context=i.context,
                source=i.source,
            )
            for i in body.iocs
        ]

    def health(self) -> str:
        """'ok' when the service answers its health check with 200, otherwise 'down'."""
        try:
            with self._client(5.0) as client:
                return "ok" if client.get(HEALTH_PATH).status_code == 200 else "down"
        except httpx.HTTPError:
            return "down"
