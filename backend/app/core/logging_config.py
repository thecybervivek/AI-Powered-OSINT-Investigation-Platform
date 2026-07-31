import json
import logging
import logging.handlers
import sys
from datetime import datetime
from datetime import timezone
from pathlib import Path

from backend.app.core.request_context import get_request_id

LOG_DIR = Path("logs")


class RequestIdFilter(logging.Filter):
    """
    Injects the current request's correlation ID (set by
    RequestLoggingMiddleware via a ContextVar) into every log record
    that doesn't already carry one explicitly. This is what lets a
    deeply-nested integration's `logger.warning(...)` call end up
    tagged with the same request_id as the top-level request log line,
    with zero changes needed at any individual call site.
    """

    def filter(self, record: logging.LogRecord) -> bool:

        if not hasattr(record, "request_id") or record.request_id is None:
            record.request_id = get_request_id()

        return True


class JsonFormatter(logging.Formatter):
    """
    Minimal dependency-free JSON log formatter. Keeps requirements.txt
    unchanged rather than pulling in python-json-logger for one formatter.
    """

    def format(
        self,
        record: logging.LogRecord,
    ) -> str:

        payload = {
            "timestamp": datetime.fromtimestamp(
                record.created,
                tz=timezone.utc,
            ).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)

        for key in (
            "request_id",
            "user_id",
            "path",
            "method",
            "status_code",
            "duration_ms",
            "event",
        ):
            value = getattr(record, key, None)

            if value is not None:
                payload[key] = value

        return json.dumps(payload)


def configure_logging(
    *,
    debug: bool = False,
) -> None:

    LOG_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG if debug else logging.INFO)
    root_logger.handlers.clear()

    request_id_filter = RequestIdFilter()

    json_formatter = JsonFormatter()

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(json_formatter)
    console_handler.addFilter(request_id_filter)
    root_logger.addHandler(console_handler)

    app_file_handler = logging.handlers.RotatingFileHandler(
        LOG_DIR / "app.log",
        maxBytes=10 * 1024 * 1024,
        backupCount=5,
        encoding="utf-8",
    )
    app_file_handler.setFormatter(json_formatter)
    app_file_handler.addFilter(request_id_filter)
    root_logger.addHandler(app_file_handler)

    error_file_handler = logging.handlers.RotatingFileHandler(
        LOG_DIR / "error.log",
        maxBytes=10 * 1024 * 1024,
        backupCount=5,
        encoding="utf-8",
    )
    error_file_handler.setLevel(logging.ERROR)
    error_file_handler.setFormatter(json_formatter)
    error_file_handler.addFilter(request_id_filter)
    root_logger.addHandler(error_file_handler)

    audit_logger = logging.getLogger("audit")
    audit_logger.setLevel(logging.INFO)
    audit_logger.propagate = False

    audit_file_handler = logging.handlers.RotatingFileHandler(
        LOG_DIR / "audit.log",
        maxBytes=10 * 1024 * 1024,
        backupCount=10,
        encoding="utf-8",
    )
    audit_file_handler.setFormatter(json_formatter)
    audit_file_handler.addFilter(request_id_filter)
    audit_logger.addHandler(audit_file_handler)


def get_audit_logger() -> logging.Logger:
    return logging.getLogger("audit")
