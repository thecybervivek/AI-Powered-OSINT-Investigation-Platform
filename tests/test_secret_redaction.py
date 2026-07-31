import logging

import httpx
import pytest

from backend.app.core.config import Settings
from backend.app.core.logging_config import RequestIdFilter
from backend.app.core.request_context import get_request_id
from backend.app.core.request_context import set_request_id
from backend.app.integrations.base import AsyncBaseIntegration
from backend.app.models.investigation import ModuleResultStatus
from backend.app.utils.redaction import redact_secrets


# ==========================================================
# redact_secrets()
# ==========================================================

@pytest.mark.parametrize(
    "raw,must_not_contain",
    [
        (
            "Client error '401' for url "
            "'https://api.example.com/x?api_key=TEST_API_KEY_VALUE&q=y'",
            "TEST_API_KEY_VALUE",
        ),
        (
            "https://api.example.com/x?access_key=ABCDEF&format=json",
            "ABCDEF",
        ),
        (
            "https://api.example.com/x?token=eyJhbGciOiJIUzI1NiJ9.abc.def",
            "eyJhbGciOiJIUzI1NiJ9.abc.def",
        ),
        (
            "Authorization: Bearer TEST_BEARER_TOKEN_ABCDEF123456",
            "TEST_BEARER_TOKEN_ABCDEF123456",
        ),
        (
            "Cookie: session=abc123def456; other=value",
            "abc123def456",
        ),
    ],
)
def test_redact_secrets_strips_known_credential_patterns(
    raw,
    must_not_contain,
):
    redacted = redact_secrets(raw)

    assert must_not_contain not in redacted
    assert "REDACTED" in redacted


def test_redact_secrets_preserves_non_sensitive_content():
    raw = "https://api.example.com/lookup?number=555&format=json"
    redacted = redact_secrets(raw)

    assert redacted == raw


def test_redact_secrets_handles_none_and_empty():
    assert redact_secrets(None) is None
    assert redact_secrets("") == ""


# ==========================================================
# Settings repr/str redaction
# ==========================================================

def test_settings_repr_redacts_secret_key(monkeypatch):
    monkeypatch.setenv(
        "SECRET_KEY",
        "TEST_SECRET_VALUE_THAT_MUST_NEVER_APPEAR_IN_LOGS",
    )
    monkeypatch.setenv(
        "DATABASE_URL",
        "postgresql+psycopg://user:TEST_DATABASE_PASSWORD@db/x",
    )

    fresh_settings = Settings()
    text = repr(fresh_settings)

    assert "TEST_SECRET_VALUE_THAT_MUST_NEVER_APPEAR_IN_LOGS" not in text
    assert "TEST_DATABASE_PASSWORD" not in text
    assert "REDACTED" in text


def test_settings_repr_redacts_provider_api_keys(monkeypatch):
    monkeypatch.setenv(
        "VIRUSTOTAL_API_KEY",
        "TEST_VIRUSTOTAL_API_KEY_VALUE",
    )

    fresh_settings = Settings()
    text = repr(fresh_settings)
    plain_text = str(fresh_settings)

    assert "TEST_VIRUSTOTAL_API_KEY_VALUE" not in text
    assert "TEST_VIRUSTOTAL_API_KEY_VALUE" not in plain_text


def test_settings_repr_does_not_redact_non_sensitive_fields(
    monkeypatch,
):
    fresh_settings = Settings()
    text = repr(fresh_settings)

    assert "APP_NAME=" in text


# ==========================================================
# Base-class integration error handling never leaks
# credentials end to end.
# ==========================================================

@pytest.mark.anyio
async def test_integration_run_redacts_leaked_query_secret_end_to_end():
    class _LeakyIntegration(AsyncBaseIntegration):
        source_name = "leaky_test"

        def is_configured(self):
            return True

        async def _query(self, target):
            request = httpx.Request(
                "GET",
                (
                    "https://api.example.com/lookup"
                    f"?api_key=TEST_PROVIDER_API_KEY_VALUE&q={target}"
                ),
            )
            response = httpx.Response(
                401,
                request=request,
            )
            response.raise_for_status()

    result = await _LeakyIntegration().run("somevalue")

    assert result.status == ModuleResultStatus.FAILED
    assert "TEST_PROVIDER_API_KEY_VALUE" not in (
        result.error_message or ""
    )
    assert "REDACTED" in (result.error_message or "")


# ==========================================================
# Request correlation ID propagation
# ==========================================================

def test_request_id_context_var_roundtrip():
    set_request_id("test-id-12345")

    assert get_request_id() == "test-id-12345"

    set_request_id(None)

    assert get_request_id() is None


def test_request_id_filter_injects_current_context_id():
    set_request_id("filter-test-id-999")

    record = logging.LogRecord(
        name="app.some.nested.module",
        level=logging.WARNING,
        pathname=__file__,
        lineno=1,
        msg="test message",
        args=(),
        exc_info=None,
    )

    result = RequestIdFilter().filter(record)

    assert result is True
    assert record.request_id == "filter-test-id-999"

    set_request_id(None)


def test_request_id_filter_does_not_overwrite_explicit_value():
    set_request_id("context-id")

    record = logging.LogRecord(
        name="app.test",
        level=logging.WARNING,
        pathname=__file__,
        lineno=1,
        msg="test",
        args=(),
        exc_info=None,
    )
    record.request_id = "explicitly-set-id"

    RequestIdFilter().filter(record)

    assert record.request_id == "explicitly-set-id"

    set_request_id(None)


# ==========================================================
# SSRF policy rejections are logged as security events
# ==========================================================

def test_ssrf_rejection_logs_security_event(caplog):
    from backend.app.utils.http_client import assert_public_url

    with caplog.at_level(
        logging.WARNING,
        logger="app.utils.http_client",
    ):
        with pytest.raises(ValueError):
            assert_public_url("http://169.254.169.254/")

    security_events = [
        record
        for record in caplog.records
        if getattr(record, "event", None)
        == "ssrf_policy_rejected"
    ]

    assert len(security_events) == 1