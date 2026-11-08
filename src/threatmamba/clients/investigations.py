"""HTTP transport to saved IOC investigations; the IOC service owns their state, rules and answers."""

import httpx

from threatmamba.clients.errors import ServiceError

# Only these request headers mean anything to the IOC service's investigation routes.
FORWARDED_HEADERS = ("content-type", "idempotency-key")


class IOCInvestigationClient:
    def __init__(self, base_url: str, timeout_s: float = 600.0, transport: httpx.AsyncBaseTransport | None = None):
        self.base_url = base_url.rstrip("/")
        self.timeout_s = timeout_s
        self.transport = transport

    async def forward(self, method: str, path: str, *, content: bytes, params, headers) -> httpx.Response:
        """Send one request unchanged (body, query, the headers above) and return the answer unchanged."""
        sent = {name: headers[name] for name in FORWARDED_HEADERS if name in headers}
        try:
            async with httpx.AsyncClient(
                base_url=self.base_url, timeout=self.timeout_s, transport=self.transport, follow_redirects=False
            ) as client:
                return await client.request(method, path, content=content, params=params, headers=sent)
        except httpx.HTTPError as exc:
            raise ServiceError("ioc", f"{type(exc).__name__}: {exc}") from exc
