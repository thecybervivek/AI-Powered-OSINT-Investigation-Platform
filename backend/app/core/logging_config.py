import json
import logging
import logging.handlers
import sys
from datetime import datetime
from datetime import timezone
from pathlib import Path

LOG_DIR = Path("logs")


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

    json_formatter = JsonFormatter()

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(json_formatter)
    root_logger.addHandler(console_handler)

    app_file_handler = logging.handlers.RotatingFileHandler(
        LOG_DIR / "app.log",
        maxBytes=10 * 1024 * 1024,
        backupCount=5,
        encoding="utf-8",
    )
    app_file_handler.setFormatter(json_formatter)
    root_logger.addHandler(app_file_handler)

    error_file_handler = logging.handlers.RotatingFileHandler(
        LOG_DIR / "error.log",
        maxBytes=10 * 1024 * 1024,
        backupCount=5,
        encoding="utf-8",
    )
    error_file_handler.setLevel(logging.ERROR)
    error_file_handler.setFormatter(json_formatter)
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
    audit_logger.addHandler(audit_file_handler)


def get_audit_logger() -> logging.Logger:
    return logging.getLogger("audit")
