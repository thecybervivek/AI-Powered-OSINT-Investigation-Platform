import asyncio

import httpx

from backend.app.core.config import settings
from backend.app.integrations.base import AsyncBaseIntegration
from backend.app.integrations.base import IntegrationResult
from backend.app.integrations.exceptions import IntegrationRateLimitError
from backend.app.integrations.exceptions import IntegrationTimeoutError
from backend.app.models.investigation import ModuleResultStatus
from backend.app.utils.http_client import request_with_retry


class URLScanIntegration(AsyncBaseIntegration):
    """
    Submits a URL to urlscan.io for live sandboxed analysis: the target
    page is actually loaded in a headless browser, and urlscan.io
    reports the final redirect chain, page title, the resolved
    IP/server, and a maliciousness verdict.

    Unlike the other Milestone 5 sources, this one works *without* an
    API key (public submissions are allowed at a lower rate/visibility
    tier), so it is never SKIPPED - only degraded to public visibility
    when URLSCAN_API_KEY isn't set. Scanning is asynchronous: we submit,
    then poll the result endpoint until it's ready or we hit
    URLSCAN_POLL_TIMEOUT_SECONDS.
    """

    source_name = "urlscan"

    def is_configured(self) -> bool:
        # Always usable - unauthenticated public scans are supported.
        return True

    async def _query(self, target: str) -> IntegrationResult:

        headers = {"Content-Type": "application/json"}

        if settings.URLSCAN_API_KEY:
            headers["API-Key"] = settings.URLSCAN_API_KEY

        submit_url = f"{settings.URLSCAN_BASE_URL}/scan/"

        async with httpx.AsyncClient(timeout=settings.OSINT_REQUEST_TIMEOUT_SECONDS) as client:

            submit_response = await request_with_retry(
                client,
                "POST",
                submit_url,
                headers=headers,
                json={"url": target, "visibility": settings.URLSCAN_VISIBILITY},
            )

            if submit_response.status_code == 429:
                raise IntegrationRateLimitError("URLScan rate limit exceeded.")

            if submit_response.status_code not in (200, 201):

                return IntegrationResult(
                    source=self.source_name,
                    status=ModuleResultStatus.FAILED,
                    error_message=(
                        f"URLScan rejected the submission "
                        f"(HTTP {submit_response.status_code}): "
                        f"{submit_response.text[:300]}"
                    ),
                )

            submission = submit_response.json()
            result_api_url = submission.get("api")
            scan_uuid = submission.get("uuid")

            if not result_api_url:

                return IntegrationResult(
                    source=self.source_name,
                    status=ModuleResultStatus.FAILED,
                    error_message="URLScan submission did not return a result URL.",
                )

            result_payload = await self._poll_for_result(client, result_api_url)

        if result_payload is None:

            return IntegrationResult(
                source=self.source_name,
                status=ModuleResultStatus.NOT_FOUND,
                data={
                    "url": target,
                    "scan_uuid": scan_uuid,
                    "scan_result_url": submission.get("result"),
                    "analysis_complete": False,
                },
                error_message=(
                    "URLScan analysis did not complete within "
                    f"{settings.URLSCAN_POLL_TIMEOUT_SECONDS:.0f}s; the scan "
                    "may still finish shortly - check scan_result_url directly."
                ),
            )

        page = result_payload.get("page", {})
        verdicts = result_payload.get("verdicts", {}).get("overall", {})
        lists = result_payload.get("lists", {})

        data = {
            "url": target,
            "scan_uuid": scan_uuid,
            "scan_result_url": submission.get("result"),
            "analysis_complete": True,
            "final_url": page.get("url"),
            "page_title": page.get("title"),
            "resolved_ip": page.get("ip"),
            "resolved_country": page.get("country"),
            "server": page.get("server"),
            "malicious": verdicts.get("malicious", False),
            "verdict_score": verdicts.get("score"),
            "verdict_categories": verdicts.get("categories", []),
            "related_ips": lists.get("ips", []),
            "related_domains": lists.get("domains", []),
        }

        return IntegrationResult(
            source=self.source_name,
            status=ModuleResultStatus.SUCCESS,
            data=data,
        )

    async def _poll_for_result(
        self,
        client: httpx.AsyncClient,
        result_api_url: str,
    ) -> dict | None:

        elapsed = 0.0

        while elapsed < settings.URLSCAN_POLL_TIMEOUT_SECONDS:

            try:
                response = await request_with_retry(
                    client,
                    "GET",
                    result_api_url,
                    max_retries=0,
                )

            except IntegrationTimeoutError:
                response = None

            if response is not None and response.status_code == 200:
                return response.json()

            await asyncio.sleep(settings.URLSCAN_POLL_INTERVAL_SECONDS)
            elapsed += settings.URLSCAN_POLL_INTERVAL_SECONDS

        return None
