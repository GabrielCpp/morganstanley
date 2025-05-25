from fastapi import Request, FastAPI
from fastapi.responses import JSONResponse
from fastapi.exception_handlers import RequestValidationError
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.status import HTTP_500_INTERNAL_SERVER_ERROR
import logging

HANDLERS = {}


class ErrorHandlerMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        try:
            return await call_next(request)
        except Exception as exc:
            error_type = type(exc)
            handler = HANDLERS.get(error_type)

            if handler:
                status_code, message = handler(exc)
                return JSONResponse(
                    status_code=status_code, content={"detail": message}
                )

            # Unknown error: log and return 500
            logger = logging.getLogger("uvicorn.error")
            logger.error("Unhandled exception", exc_info=exc)
            return JSONResponse(
                status_code=HTTP_500_INTERNAL_SERVER_ERROR,
                content={"detail": "Internal Server Error"},
            )
