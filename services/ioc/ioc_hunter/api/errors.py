"""Map shared domain failures to HTTP without changing compatibility endpoints."""

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from ..workflow.errors import WorkflowServiceError


def error_response(request: Request, status: int, code: str, message: str, details=None):
    return JSONResponse(
        status_code=status,
        content={
            "error": {
                "code": code,
                "message": message,
                "run_id": request.path_params.get("run_id"),
                "step_id": request.path_params.get("step_id"),
                "details": details or {},
            }
        },
    )


def install_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(WorkflowServiceError)
    async def workflow_error(request: Request, exc: WorkflowServiceError):
        return error_response(request, exc.status, exc.code, str(exc), exc.details)

    @app.exception_handler(RequestValidationError)
    async def validation_error(request: Request, exc: RequestValidationError):
        if not request.url.path.startswith("/v1/investigations"):
            # Preserve the established FastAPI format on primitive endpoints.
            from fastapi.exception_handlers import request_validation_exception_handler

            return await request_validation_exception_handler(request, exc)
        failures = [{"loc": list(item["loc"]), "type": item["type"], "msg": item["msg"]} for item in exc.errors()]
        return error_response(request, 422, "invalid_request", "The request is invalid.", {"errors": failures})

    @app.exception_handler(Exception)
    async def unexpected_error(request: Request, exc: Exception):
        if not request.url.path.startswith("/v1/investigations"):
            return JSONResponse(status_code=500, content={"detail": "Internal Server Error"})
        return error_response(request, 500, "internal_error", "The investigation operation could not be completed.")
