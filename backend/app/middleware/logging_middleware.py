import logging
import time
import traceback
import uuid

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from backend.app.core.request_context import set_request_id
from backend.app.utils.redaction import redact_secrets

logger = logging.getLogger("app.request")


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """
    Attaches a request ID to every request/response pair (both on
    request.state, for handlers that want it directly, and on a
    ContextVar, so any log statement anywhere in the async call stack -
    services, integrations, several layers down - is automatically
    correlated without threading the ID through every function
    signature) and logs method, path, status code, and duration.
    """

    async def dispatch(
        self,
        request: Request,
        call_next,
    ) -> Response:

        request_id = str(uuid.uuid4())
        request.state.request_id = request_id
        set_request_id(request_id)

        start = time.perf_counter()

        try:
            response = await call_next(request)

        except Exception:
            duration_ms = round((time.perf_counter() - start) * 1000, 2)

            # Logged as a formatted, redacted string rather than via
            # logger.exception()'s automatic traceback attachment -
            # the traceback can contain an httpx exception whose own
            # __str__ embeds the full request URL (including any
            # query-string API key), and text-based redaction can't
            # reach content the formatter attaches out-of-band.
            safe_traceback = redact_secrets(traceback.format_exc())

            logger.error(
                "Unhandled exception while processing request.\n%s",
                safe_traceback,
                extra={
                    "request_id": request_id,
                    "path": request.url.path,
                    "method": request.method,
                    "duration_ms": duration_ms,
                },
            )
            raise

        duration_ms = round((time.perf_counter() - start) * 1000, 2)

        logger.info(
            "request completed",
            extra={
                "request_id": request_id,
                "path": request.url.path,
                "method": request.method,
                "status_code": response.status_code,
                "duration_ms": duration_ms,
            },
        )

        response.headers["X-Request-ID"] = request_id

        return response
