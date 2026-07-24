import base64

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


def _url_to_vt_id(url: str) -> str:
    """
    VirusTotal identifies URLs by the base64 (URL-safe, unpadded)
    encoding of the URL string itself - documented at
    https://docs.virustotal.com/reference/url and used instead of a
    numeric ID so any client can compute it without an extra lookup.
    """

    return base64.urlsafe_b64encode(url.encode("utf-8")).decode("utf-8").rstrip("=")


class VirusTotalURLIntegration(AsyncBaseIntegration):
    """
    Looks up a URL's existing VirusTotal analysis. If VirusTotal has
    never seen the URL before (404), it is submitted for a fresh scan
    and the result is reported as "submitted" - VT scans run
    asynchronously server-side, so a first-time URL won't have a
    verdict available in the same request (this mirrors how VT's own
    web UI behaves for brand-new links).

    Optional integration: requires VIRUSTOTAL_API_KEY.
    """

    source_name = "virustotal_url"

    def is_configured(self) -> bool:
        return bool(settings.VIRUSTOTAL_API_KEY)

    async def _query(self, target: str) -> IntegrationResult:

        headers = {"x-apikey": settings.VIRUSTOTAL_API_KEY}
        url_id = _url_to_vt_id(target)
        lookup_url = f"{settings.VIRUSTOTAL_BASE_URL}/urls/{url_id}"

        async with httpx.AsyncClient(timeout=settings.OSINT_REQUEST_TIMEOUT_SECONDS) as client:

            response = await request_with_retry(client, "GET", lookup_url, headers=headers)

            if response.status_code == 401:
                raise IntegrationAuthError("VirusTotal rejected the configured API key.")

            if response.status_code == 429:
                raise IntegrationRateLimitError("VirusTotal rate limit exceeded.")

            if response.status_code == 404:
                return await self._submit_for_analysis(client, headers, target)

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
                "url": target,
                "known_to_virustotal": True,
                "final_url": attributes.get("last_final_url", target),
                "title": attributes.get("title"),
                "reputation_score": attributes.get("reputation"),
                "tags": attributes.get("tags", []),
                "analysis_stats": stats,
                "flagged_vendors": flagged_vendors,
                "categories": attributes.get("categories", {}),
                "last_analysis_date": attributes.get("last_analysis_date"),
            }

            return IntegrationResult(
                source=self.source_name,
                status=ModuleResultStatus.SUCCESS,
                data=data,
            )

    async def _submit_for_analysis(
        self,
        client: httpx.AsyncClient,
        headers: dict,
        target: str,
    ) -> IntegrationResult:

        submit_url = f"{settings.VIRUSTOTAL_BASE_URL}/urls"

        response = await request_with_retry(
            client,
            "POST",
            submit_url,
            headers=headers,
            data={"url": target},
        )

        if response.status_code == 429:
            raise IntegrationRateLimitError("VirusTotal rate limit exceeded.")

        if response.status_code not in (200, 201):

            return IntegrationResult(
                source=self.source_name,
                status=ModuleResultStatus.FAILED,
                error_message=(
                    f"VirusTotal rejected the URL submission "
                    f"(HTTP {response.status_code})."
                ),
            )

        analysis_id = response.json().get("data", {}).get("id")

        return IntegrationResult(
            source=self.source_name,
            status=ModuleResultStatus.NOT_FOUND,
            data={
                "url": target,
                "known_to_virustotal": False,
                "submitted_for_analysis": True,
                "analysis_id": analysis_id,
            },
            error_message=(
                "This URL had no prior VirusTotal analysis and has just "
                "been submitted for scanning; re-run the investigation "
                "in a minute or two for a verdict."
            ),
        )
