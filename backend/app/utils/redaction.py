import re

# Query-string / form-encoded "key=value" pairs where the key name
# suggests a credential. Deliberately broad (catches api_key, apikey,
# access_key, apiKey, auth_token, x-api-key as a query param, etc.)
# since new providers with new key-naming conventions get added
# regularly - a narrow allowlist would silently stop protecting the
# next one.
_QUERY_PARAM_SECRET_PATTERN = re.compile(
    r"(?i)\b((?:api[-_]?key|access[-_]?key|auth[-_]?(?:key|token)|"
    r"secret(?:[-_]?key)?|token|password|passwd|pwd|session[-_]?id)"
    r")=([^&\s'\"]+)"
)

# HTTP Authorization / Cookie header values, in case a raw header dump
# ever ends up embedded in an error message or log line.
_AUTH_HEADER_PATTERN = re.compile(
    r"(?i)\b(authorization|cookie|set-cookie|x-api-key)\s*[:=]\s*"
    r"([^\s,;]+(?:\s+[^\s,;]+)?)"
)

_REDACTED = "***REDACTED***"


def redact_secrets(text: str | None) -> str | None:
    """
    Strips likely-credential values out of free-text error messages /
    log lines before they're logged or persisted. This is a defensive
    second layer, not a substitute for integrations correctly avoiding
    raw exception text in the first place - it exists specifically
    because httpx exceptions (e.g. HTTPStatusError) embed the full
    request URL - including any query-string API key - in their own
    __str__(), and it only takes one future integration calling
    response.raise_for_status() instead of checking status codes
    manually for that key to reach a log line or, worse, the
    error_message field returned to API clients.
    """

    if not text:
        return text

    redacted = _QUERY_PARAM_SECRET_PATTERN.sub(
        lambda m: f"{m.group(1)}={_REDACTED}", text
    )
    redacted = _AUTH_HEADER_PATTERN.sub(
        lambda m: f"{m.group(1)}: {_REDACTED}", redacted
    )

    return redacted
