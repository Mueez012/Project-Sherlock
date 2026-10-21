"""The one error a service client raises, whatever went wrong (unreachable, HTTP error, malformed answer)."""


class ServiceError(RuntimeError):
    def __init__(self, service: str, detail: str) -> None:
        super().__init__(f"{service}: {detail}")
        self.service = service
        self.detail = detail
