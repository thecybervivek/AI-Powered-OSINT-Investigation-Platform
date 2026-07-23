import logging
import time
from abc import ABC
from abc import abstractmethod
from dataclasses import dataclass
from dataclasses import field
from typing import Any

import httpx

from backend.app.integrations.exceptions import IntegrationTimeoutError
from backend.app.models.investigation import ModuleResultStatus

logger = logging.getLogger("app.integrations")


@dataclass
class IntegrationResult:
    """
    Normalized shape every integration must return, regardless of the
    upstream source's own response format. This is what gets persisted
    into InvestigationResult.data.
    """

    source: str
    status: ModuleResultStatus
    data: dict[str, Any] = field(default_factory=dict)
    raw_response: dict[str, Any] | None = None
    latency_ms: int | None = None
    error_message: str | None = None


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

            return IntegrationResult(
                source=self.source_name,
                status=ModuleResultStatus.SKIPPED,
                error_message=(
                    f"{self.source_name} is not configured "
                    f"(missing API key/setting)."
                ),
            )

        start = time.perf_counter()

        try:
            result = await self._query(target)
            result.latency_ms = round((time.perf_counter() - start) * 1000)
            return result

        except IntegrationTimeoutError as error:

            logger.warning(
                "Async integration timed out.",
                extra={"event": f"{self.source_name}_timeout"},
            )

            return IntegrationResult(
                source=self.source_name,
                status=ModuleResultStatus.FAILED,
                latency_ms=round((time.perf_counter() - start) * 1000),
                error_message=str(error),
            )

        except Exception as error:

            logger.warning(
                "Async integration call failed: %s",
                error,
                extra={"event": f"{self.source_name}_error"},
            )

            return IntegrationResult(
                source=self.source_name,
                status=ModuleResultStatus.FAILED,
                latency_ms=round((time.perf_counter() - start) * 1000),
                error_message=str(error),
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

            return IntegrationResult(
                source=self.source_name,
                status=ModuleResultStatus.SKIPPED,
                error_message=(
                    f"{self.source_name} is not configured "
                    f"(missing API key/setting)."
                ),
            )

        start = time.perf_counter()

        try:
            result = self._query(target)
            result.latency_ms = round(
                (time.perf_counter() - start) * 1000,
            )
            return result

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
            )
