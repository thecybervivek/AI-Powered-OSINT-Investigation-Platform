import logging
import time
from abc import ABC
from abc import abstractmethod
from dataclasses import dataclass
from dataclasses import field
from datetime import datetime
from datetime import timezone
from typing import Any

import httpx

from backend.app.integrations.exceptions import IntegrationRateLimitError
from backend.app.integrations.exceptions import IntegrationTimeoutError
from backend.app.models.investigation import ModuleResultStatus
from backend.app.utils.redaction import redact_secrets

logger = logging.getLogger("app.integrations")


@dataclass
class IntegrationResult:
    """
    Normalized shape every integration must return, regardless of the
    upstream source's own response format. This is what gets persisted
    into InvestigationResult.data.

    Provider Status Model (spec section 7): every result exposes
    provider name (`source`), status, latency, and an explicit,
    separate reason depending on WHY it doesn't have a conclusive
    answer - `config_reason` when the provider was never attempted
    because it isn't configured, vs `error_message` when it was
    attempted and failed. Collapsing those two into one field is
    exactly the "SKIPPED == FAILED" ambiguity the spec calls out;
    keeping them distinct lets callers/frontends render "not
    configured" differently from "attempted and failed".

    `category` and `confidence` are optional, additive fields -
    existing integrations that don't set them keep working unchanged
    (default None), while new/updated integrations can start
    populating them to feed a fuller Provider Status section.
    """

    source: str
    status: ModuleResultStatus
    data: dict[str, Any] = field(default_factory=dict)
    raw_response: dict[str, Any] | None = None
    latency_ms: int | None = None
    error_message: str | None = None
    config_reason: str | None = None
    category: str | None = None
    confidence: float | None = None
    observed_at: datetime | None = None

    def to_provider_status_dict(self) -> dict[str, Any]:
        """
        The full per-provider envelope spec section 7 asks for:
        provider name, category, status, latency, timestamp,
        confidence (if applicable), error reason (if failed),
        configuration reason (if skipped), and a raw-evidence
        reference. Used to build the "Provider Status" frontend
        section without every service re-assembling this by hand.
        """

        return {
            "provider": self.source,
            "category": self.category,
            "status": self.status.value,
            "latency_ms": self.latency_ms,
            "observed_at": self.observed_at.isoformat() if self.observed_at else None,
            "confidence": self.confidence,
            "error_reason": self.error_message,
            "configuration_reason": self.config_reason,
            "has_raw_evidence": bool(self.raw_response),
        }


class AsyncBaseIntegration(ABC):
    """
    Async counterpart to BaseIntegration for sources that need to run
    concurrently (e.g. fanning a single username out across dozens of
    platforms). Mirrors the same is_configured()/_query() contract and
    the same normalized-result + error-handling guarantees, just on the
    asyncio event loop instead of a blocking httpx.Client.
    """

    source_name: str = "base_async"
    timeout_seconds: float = 10.0

    @abstractmethod
    def is_configured(self) -> bool:
        raise NotImplementedError

    @abstractmethod
    async def _query(self, target: str) -> IntegrationResult:
        raise NotImplementedError

    async def run(self, target: str) -> IntegrationResult:

        if not self.is_configured():

            # `error_message` is kept populated here (as before) so
            # every existing caller that persists/renders it for a
            # SKIPPED result keeps working unchanged; `config_reason`
            # carries the *same* text under its own, semantically
            # distinct name (spec section 7: configuration reason must
            # be distinguishable from an error reason) for callers that
            # adopt it going forward - see to_provider_status_dict().
            reason = (
                f"{self.source_name} is not configured "
                f"(missing API key/setting)."
            )

            return IntegrationResult(
                source=self.source_name,
                status=ModuleResultStatus.SKIPPED,
                error_message=reason,
                config_reason=reason,
                observed_at=datetime.now(timezone.utc),
            )

        start = time.perf_counter()

        try:
            result = await self._query(target)
            result.latency_ms = round((time.perf_counter() - start) * 1000)
            result.observed_at = result.observed_at or datetime.now(timezone.utc)
            return result

        except IntegrationRateLimitError as error:

            # Previously fell through to the generic `except Exception`
            # branch below and was reported as FAILED, indistinguishable
            # from a genuine provider error (spec section 7/10: FAILED
            # and rate-limited must not be collapsed into one state).
            safe_message = redact_secrets(str(error))

            logger.warning(
                "Async integration was rate-limited.",
                extra={"event": f"{self.source_name}_rate_limited"},
            )

            return IntegrationResult(
                source=self.source_name,
                status=ModuleResultStatus.RATE_LIMITED,
                latency_ms=round((time.perf_counter() - start) * 1000),
                error_message=safe_message,
                observed_at=datetime.now(timezone.utc),
            )

        except IntegrationTimeoutError as error:

            safe_message = redact_secrets(str(error))

            logger.warning(
                "Async integration timed out.",
                extra={"event": f"{self.source_name}_timeout"},
            )

            return IntegrationResult(
                source=self.source_name,
                status=ModuleResultStatus.FAILED,
                latency_ms=round((time.perf_counter() - start) * 1000),
                error_message=safe_message,
                observed_at=datetime.now(timezone.utc),
            )

        except Exception as error:

            safe_message = redact_secrets(str(error))

            logger.warning(
                "Async integration call failed: %s",
                safe_message,
                extra={"event": f"{self.source_name}_error"},
            )

            return IntegrationResult(
                source=self.source_name,
                status=ModuleResultStatus.FAILED,
                latency_ms=round((time.perf_counter() - start) * 1000),
                error_message=safe_message,
                observed_at=datetime.now(timezone.utc),
            )


class BaseIntegration(ABC):
    """
    Every third-party OSINT source (Sherlock, Maigret, WhatsMyName, Holehe,
    EmailRep, HIBP, VirusTotal, SecurityTrails, IPInfo, AbuseIPDB,
    URLScan, Google Safe Browsing, NumVerify, ...) implements this
    interface. This keeps the service layer source-agnostic: it calls
    `.run(target)` and gets back a normalized IntegrationResult no
    matter which tool answered.
    """

    #: Unique, stable identifier used as InvestigationResult.source
    source_name: str = "base"

    #: Seconds to wait before treating the call as timed out
    timeout_seconds: float = 10.0

    def __init__(
        self,
        client: httpx.Client | None = None,
    ) -> None:

        self._owns_client = client is None
        self.client = client or httpx.Client(
            timeout=self.timeout_seconds,
        )

    def __enter__(self) -> "BaseIntegration":
        return self

    def __exit__(self, *exc_info) -> None:
        if self._owns_client:
            self.client.close()

    @abstractmethod
    def is_configured(self) -> bool:
        """
        Return False if a required API key/setting is missing, so the
        caller can mark this source as SKIPPED instead of FAILED.
        """
        raise NotImplementedError

    @abstractmethod
    def _query(self, target: str) -> IntegrationResult:
        """
        Subclasses implement the actual upstream call + response
        normalization here. Raise IntegrationError subclasses on failure;
        run() converts them into a normalized IntegrationResult.
        """
        raise NotImplementedError

    def run(
        self,
        target: str,
    ) -> IntegrationResult:

        if not self.is_configured():

            # See AsyncBaseIntegration.run()'s matching branch for why
            # both error_message and config_reason carry this text.
            reason = (
                f"{self.source_name} is not configured "
                f"(missing API key/setting)."
            )

            return IntegrationResult(
                source=self.source_name,
                status=ModuleResultStatus.SKIPPED,
                error_message=reason,
                config_reason=reason,
                observed_at=datetime.now(timezone.utc),
            )

        start = time.perf_counter()

        try:
            result = self._query(target)
            result.latency_ms = round(
                (time.perf_counter() - start) * 1000,
            )
            result.observed_at = result.observed_at or datetime.now(timezone.utc)
            return result

        except IntegrationRateLimitError as error:

            # See AsyncBaseIntegration.run()'s matching branch: this was
            # previously indistinguishable from a generic FAILED result.
            safe_message = redact_secrets(str(error))

            logger.warning(
                "Integration was rate-limited.",
                extra={"event": f"{self.source_name}_rate_limited"},
            )

            return IntegrationResult(
                source=self.source_name,
                status=ModuleResultStatus.RATE_LIMITED,
                latency_ms=round((time.perf_counter() - start) * 1000),
                error_message=safe_message,
                observed_at=datetime.now(timezone.utc),
            )

        except IntegrationTimeoutError as error:

            logger.warning(
                "Integration timed out.",
                extra={"event": f"{self.source_name}_timeout"},
            )

            return IntegrationResult(
                source=self.source_name,
                status=ModuleResultStatus.FAILED,
                latency_ms=round((time.perf_counter() - start) * 1000),
                error_message=str(error),
                observed_at=datetime.now(timezone.utc),
            )

        except Exception as error:

            logger.warning(
                "Integration call failed: %s",
                error,
                extra={"event": f"{self.source_name}_error"},
            )

            return IntegrationResult(
                source=self.source_name,
                status=ModuleResultStatus.FAILED,
                latency_ms=round((time.perf_counter() - start) * 1000),
                error_message=str(error),
                observed_at=datetime.now(timezone.utc),
            )
