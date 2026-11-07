"""HTTP transport to saved IOC investigations; the IOC service owns their state."""

import httpx

from threatmamba.clients.errors import ServiceError


class IOCInvestigationClient:
    def __init__(self, base_url: str, timeout_s: float = 600.0, transport: httpx.BaseTransport | None = None) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout_s = timeout_s
        self.transport = transport

    def request(
        self,
        method: str,
        path: str,
        *,
        body: dict | None = None,
        params: dict | None = None,
        authorization: str | None = None,
        idempotency_key: str | None = None,
    ) -> httpx.Response:
        headers = {}
        if authorization is not None:
            headers["Authorization"] = authorization
        if idempotency_key is not None:
            headers["Idempotency-Key"] = idempotency_key
        try:
            with httpx.Client(
                base_url=self.base_url, timeout=self.timeout_s, transport=self.transport, follow_redirects=False
            ) as client:
                return client.request(method, path, json=body, params=params, headers=headers)
        except httpx.HTTPError as exc:
            raise ServiceError("ioc", f"{type(exc).__name__}: {exc}") from exc
