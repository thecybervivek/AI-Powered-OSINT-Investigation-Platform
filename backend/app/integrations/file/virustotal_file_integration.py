import httpx

from backend.app.core.config import settings
from backend.app.integrations.base import AsyncBaseIntegration
from backend.app.integrations.base import IntegrationResult
from backend.app.integrations.exceptions import IntegrationAuthError
from backend.app.integrations.exceptions import IntegrationRateLimitError
from backend.app.integrations.virustotal_common import extract_flagged_vendors
from backend.app.integrations.virustotal_common import summarize_analysis_stats
from backend.app.models.investigation import ModuleResultStatus
from backend.app.utils.http_client import request_with_retry


class VirusTotalFileIntegration(AsyncBaseIntegration):
    """
    Queries VirusTotal's `/files/{sha256}` endpoint - a hash LOOKUP
    against VT's existing corpus, not a file upload/submission. Uploads
    are a separate, heavier-weight VT endpoint intentionally not used
    here: a freshly-created file's sha256 simply won't exist there yet,
    and that "unknown to VT" result is itself useful signal for the
    risk engine rather than a reason to submit arbitrary user files to
    a third-party service.

    Optional integration: requires VIRUSTOTAL_API_KEY. Reports
    status=skipped with a clear message when the key is absent.
    """

    source_name = "virustotal_file"

    def is_configured(self) -> bool:
        return settings.VIRUSTOTAL_FILE_LOOKUP_ENABLED and bool(settings.VIRUSTOTAL_API_KEY)

    async def _query(self, target: str) -> IntegrationResult:

        url = f"{settings.VIRUSTOTAL_BASE_URL}/files/{target}"
        headers = {"x-apikey": settings.VIRUSTOTAL_API_KEY}

        async with httpx.AsyncClient(timeout=settings.OSINT_REQUEST_TIMEOUT_SECONDS) as client:

            response = await request_with_retry(client, "GET", url, headers=headers)

        if response.status_code == 401:
            raise IntegrationAuthError("VirusTotal rejected the configured API key.")

        if response.status_code == 429:
            raise IntegrationRateLimitError("VirusTotal rate limit exceeded.")

        if response.status_code == 404:

            return IntegrationResult(
                source=self.source_name,
                status=ModuleResultStatus.NOT_FOUND,
                data={"sha256": target, "known_to_virustotal": False},
            )

        if response.status_code != 200:

            return IntegrationResult(
                source=self.source_name,
                status=ModuleResultStatus.FAILED,
                error_message=f"VirusTotal returned HTTP {response.status_code}.",
            )

        attributes = response.json().get("data", {}).get("attributes", {})

        stats = summarize_analysis_stats(attributes.get("last_analysis_stats", {}))
        flagged_vendors = extract_flagged_vendors(attributes.get("last_analysis_results", {}))

        data = {
            "sha256": target,
            "known_to_virustotal": True,
            "type_description": attributes.get("type_description"),
            "meaningful_name": attributes.get("meaningful_name"),
            "reputation_score": attributes.get("reputation"),
            "times_submitted": attributes.get("times_submitted"),
            "first_submission_date": attributes.get("first_submission_date"),
            "last_analysis_date": attributes.get("last_analysis_date"),
            "signature_info": attributes.get("signature_info", {}),
            "names": (attributes.get("names") or [])[:10],
            "analysis_stats": stats,
            "flagged_vendors": flagged_vendors,
        }

        return IntegrationResult(
            source=self.source_name,
            status=ModuleResultStatus.SUCCESS,
            data=data,
        )
