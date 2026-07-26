import httpx

from backend.app.core.config import settings
from backend.app.integrations.base import AsyncBaseIntegration
from backend.app.integrations.base import IntegrationResult
from backend.app.integrations.exceptions import IntegrationAuthError
from backend.app.integrations.exceptions import IntegrationRateLimitError
from backend.app.models.investigation import ModuleResultStatus
from backend.app.utils.http_client import request_with_retry


class HybridAnalysisIntegration(AsyncBaseIntegration):
    """
    Queries Hybrid Analysis's `/search/hash` endpoint for a sha256 hash,
    returning any prior sandbox detonation report for the exact same
    file - verdict, threat score, and the antivirus detection ratio
    observed during that sandbox run.

    Optional integration: requires HYBRIDANALYSIS_API_KEY. Skips
    gracefully without one.
    """

    source_name = "hybrid_analysis"

    def is_configured(self) -> bool:
        return bool(settings.HYBRIDANALYSIS_API_KEY)

    async def _query(self, target: str) -> IntegrationResult:

        url = f"{settings.HYBRIDANALYSIS_BASE_URL}/search/hash"

        headers = {
            "api-key": settings.HYBRIDANALYSIS_API_KEY,
            "User-Agent": "Falcon Sandbox",
            "Accept": "application/json",
        }

        async with httpx.AsyncClient(timeout=settings.OSINT_REQUEST_TIMEOUT_SECONDS) as client:

            response = await request_with_retry(
                client,
                "POST",
                url,
                headers=headers,
                data={"hash": target},
            )

        if response.status_code == 401:
            raise IntegrationAuthError("Hybrid Analysis rejected the configured API key.")

        if response.status_code == 429:
            raise IntegrationRateLimitError("Hybrid Analysis rate limit exceeded.")

        if response.status_code != 200:

            return IntegrationResult(
                source=self.source_name,
                status=ModuleResultStatus.FAILED,
                error_message=f"Hybrid Analysis returned HTTP {response.status_code}.",
            )

        reports = response.json()

        if not reports:

            return IntegrationResult(
                source=self.source_name,
                status=ModuleResultStatus.NOT_FOUND,
                data={"sha256": target, "known_to_hybrid_analysis": False},
            )

        report = reports[0]

        data_out = {
            "sha256": target,
            "known_to_hybrid_analysis": True,
            "verdict": report.get("verdict"),
            "threat_score": report.get("threat_score"),
            "threat_level": report.get("threat_level"),
            "av_detect": report.get("av_detect"),
            "vx_family": report.get("vx_family"),
            "environment_description": report.get("environment_description"),
            "analysis_start_time": report.get("analysis_start_time"),
            "type": report.get("type"),
        }

        return IntegrationResult(
            source=self.source_name,
            status=ModuleResultStatus.SUCCESS,
            data=data_out,
        )
