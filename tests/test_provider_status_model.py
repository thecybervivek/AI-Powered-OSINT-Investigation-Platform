"""
Provider Status Model regression tests (spec section 7).

Covers the base.py fix: IntegrationRateLimitError previously fell
through the generic `except Exception` branch in both
BaseIntegration.run() and AsyncBaseIntegration.run() and was reported
as FAILED, indistinguishable from a genuine provider error. It now
maps to ModuleResultStatus.RATE_LIMITED distinctly. Also covers the
new config_reason/category/confidence fields and
IntegrationResult.to_provider_status_dict().
"""

import asyncio

from backend.app.integrations.base import AsyncBaseIntegration
from backend.app.integrations.base import BaseIntegration
from backend.app.integrations.base import IntegrationResult
from backend.app.integrations.exceptions import IntegrationRateLimitError
from backend.app.models.investigation import ModuleResultStatus


class _AsyncRateLimitedIntegration(AsyncBaseIntegration):
    source_name = "fake_async_source"

    def is_configured(self) -> bool:
        return True

    async def _query(self, target: str) -> IntegrationResult:
        raise IntegrationRateLimitError("Fake source rate limit exceeded.")


class _AsyncGenericFailureIntegration(AsyncBaseIntegration):
    source_name = "fake_async_source"

    def is_configured(self) -> bool:
        return True

    async def _query(self, target: str) -> IntegrationResult:
        raise ValueError("boom")


class _AsyncUnconfiguredIntegration(AsyncBaseIntegration):
    source_name = "fake_async_source"

    def is_configured(self) -> bool:
        return False

    async def _query(self, target: str) -> IntegrationResult:  # pragma: no cover
        raise AssertionError("should never be called when not configured")


class _SyncRateLimitedIntegration(BaseIntegration):
    source_name = "fake_sync_source"

    def is_configured(self) -> bool:
        return True

    def _query(self, target: str) -> IntegrationResult:
        raise IntegrationRateLimitError("Fake source rate limit exceeded.")


# ==========================================================
# AsyncBaseIntegration.run()
# ==========================================================


def test_async_run_maps_rate_limit_error_to_rate_limited_not_failed():

    result = asyncio.run(_AsyncRateLimitedIntegration().run("target"))

    assert result.status == ModuleResultStatus.RATE_LIMITED
    assert result.status != ModuleResultStatus.FAILED
    assert "rate limit" in result.error_message.lower()
    assert result.latency_ms is not None
    assert result.observed_at is not None


def test_async_run_still_maps_generic_exceptions_to_failed():

    result = asyncio.run(_AsyncGenericFailureIntegration().run("target"))

    assert result.status == ModuleResultStatus.FAILED


def test_async_run_skipped_sets_both_error_message_and_config_reason():
    """
    error_message stays populated for backward compatibility with every
    existing service that persists/renders it for a SKIPPED result;
    config_reason carries the identical text under its own name so new
    code can read a semantically distinct field going forward.
    """

    result = asyncio.run(_AsyncUnconfiguredIntegration().run("target"))

    assert result.status == ModuleResultStatus.SKIPPED
    assert result.error_message == result.config_reason
    assert "not configured" in result.error_message.lower()


# ==========================================================
# BaseIntegration.run() (sync counterpart)
# ==========================================================


def test_sync_run_maps_rate_limit_error_to_rate_limited_not_failed():

    with _SyncRateLimitedIntegration() as integration:
        result = integration.run("target")

    assert result.status == ModuleResultStatus.RATE_LIMITED
    assert result.status != ModuleResultStatus.FAILED


# ==========================================================
# IntegrationResult.to_provider_status_dict()
# ==========================================================


def test_provider_status_dict_shape_for_a_skipped_provider():

    result = IntegrationResult(
        source="numverify",
        status=ModuleResultStatus.SKIPPED,
        config_reason="numverify is not configured (missing API key/setting).",
        category="carrier_lookup",
    )

    envelope = result.to_provider_status_dict()

    assert envelope["provider"] == "numverify"
    assert envelope["status"] == "skipped"
    assert envelope["configuration_reason"]
    assert envelope["error_reason"] is None
    assert envelope["has_raw_evidence"] is False


def test_provider_status_dict_shape_for_a_successful_provider():

    result = IntegrationResult(
        source="hibp",
        status=ModuleResultStatus.SUCCESS,
        category="breach_intelligence",
        confidence=0.9,
        raw_response={"ok": True},
        latency_ms=120,
    )

    envelope = result.to_provider_status_dict()

    assert envelope["status"] == "success"
    assert envelope["confidence"] == 0.9
    assert envelope["latency_ms"] == 120
    assert envelope["has_raw_evidence"] is True
    assert envelope["configuration_reason"] is None
