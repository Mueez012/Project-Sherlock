"""RFC 9457 problem+json errors: {type, title, status, detail, code}."""
from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

PROBLEM = "application/problem+json"
TYPE_BASE = "https://sherklock.local/problems/"

TITLES = {
    400: "Bad request", 404: "Not found", 409: "Conflict", 413: "Payload too large",
    415: "Unsupported media type", 422: "Unprocessable content", 429: "Too many requests",
    500: "Internal server error", 503: "Service unavailable",
}


class ApiError(Exception):
    def __init__(self, status: int, code: str, detail: str, title: str | None = None):
        super().__init__(detail)
        self.status, self.code, self.detail = status, code, detail
        self.title = title or TITLES.get(status, "Error")


def problem(status: int, code: str, detail: str, title: str | None = None) -> JSONResponse:
    body = {"type": TYPE_BASE + code, "title": title or TITLES.get(status, "Error"),
            "status": status, "detail": detail, "code": code}
    return JSONResponse(body, status_code=status, media_type=PROBLEM)


def install(app: FastAPI) -> None:
    @app.exception_handler(ApiError)
    async def _api_error(_: Request, exc: ApiError):
        return problem(exc.status, exc.code, exc.detail, exc.title)

    @app.exception_handler(RequestValidationError)
    async def _validation(_: Request, exc: RequestValidationError):
        first = exc.errors()[0] if exc.errors() else {}
        where = ".".join(str(x) for x in first.get("loc", []) if x != "body")
        return problem(400, "bad_request", f"{where}: {first.get('msg', 'invalid request')}".strip(": "))

    @app.exception_handler(StarletteHTTPException)
    async def _http(_: Request, exc: StarletteHTTPException):
        code = {404: "not_found", 405: "method_not_allowed"}.get(exc.status_code, "http_error")
        return problem(exc.status_code, code, str(exc.detail))

    @app.exception_handler(Exception)
    async def _unexpected(_: Request, exc: Exception):
        return problem(500, "internal_error", "unexpected server error; see the server log")
