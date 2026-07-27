"""Privacy minimization helpers for optional external AI processing."""
import re
from typing import Any

_EMAIL = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I)
_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_SECRET_KEY = re.compile(r"(?i)(api[_-]?key|token|secret|password|authorization|cookie)")


def redact_for_external_ai(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(k): ("[REDACTED]" if _SECRET_KEY.search(str(k)) else redact_for_external_ai(v)) for k, v in value.items()}
    if isinstance(value, list):
        return [redact_for_external_ai(v) for v in value]
    if isinstance(value, str):
        value = _EMAIL.sub("[REDACTED_EMAIL]", value)
        value = _IPV4.sub("[REDACTED_IP]", value)
        return value[:4000]
    return value
