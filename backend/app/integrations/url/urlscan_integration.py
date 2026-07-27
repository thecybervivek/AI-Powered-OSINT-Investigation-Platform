import asyncio
import re
import httpx
from backend.app.core.config import settings
from backend.app.integrations.base import AsyncBaseIntegration, IntegrationResult
from backend.app.integrations.exceptions import IntegrationRateLimitError, IntegrationTimeoutError
from backend.app.models.investigation import ModuleResultStatus
from backend.app.utils.http_client import assert_public_url, request_with_retry

_UUID_RE = re.compile(r"^[0-9a-fA-F-]{32,36}$")

class URLScanIntegration(AsyncBaseIntegration):
    """Explicitly opt-in active third-party URL scanning."""
    source_name = "urlscan"

    def is_configured(self) -> bool:
        return bool(settings.URLSCAN_ACTIVE_SCANNING_ENABLED and settings.URLSCAN_API_KEY)

    async def _query(self, target: str) -> IntegrationResult:
        if not settings.URLSCAN_ACTIVE_SCANNING_ENABLED:
            return IntegrationResult(source=self.source_name, status=ModuleResultStatus.SKIPPED,
                                     error_message="Active third-party URL scanning is disabled by policy.")
        assert_public_url(target)
        visibility = settings.URLSCAN_VISIBILITY.lower()
        if visibility not in {"private", "unlisted"}:
            visibility = "private"
        headers = {"Content-Type": "application/json", "API-Key": settings.URLSCAN_API_KEY}
        submit_url = f"{settings.URLSCAN_BASE_URL.rstrip('/')}/scan/"
        async with httpx.AsyncClient(timeout=settings.OSINT_REQUEST_TIMEOUT_SECONDS) as client:
            response = await request_with_retry(client, "POST", submit_url, headers=headers,
                                                json={"url": target, "visibility": visibility})
            if response.status_code == 429:
                raise IntegrationRateLimitError("URLScan rate limit exceeded.")
            if response.status_code not in (200, 201):
                return IntegrationResult(source=self.source_name, status=ModuleResultStatus.FAILED,
                                         error_message=f"URLScan submission failed (HTTP {response.status_code}).")
            submission = response.json()
            scan_uuid = str(submission.get("uuid") or "")
            if not _UUID_RE.fullmatch(scan_uuid):
                return IntegrationResult(source=self.source_name, status=ModuleResultStatus.FAILED,
                                         error_message="URLScan returned an invalid scan identifier.")
            result_api_url = f"{settings.URLSCAN_BASE_URL.rstrip('/')}/result/{scan_uuid}/"
            result_payload = await self._poll_for_result(client, result_api_url)
        if result_payload is None:
            return IntegrationResult(source=self.source_name, status=ModuleResultStatus.NOT_FOUND,
                                     data={"url": target, "scan_uuid": scan_uuid, "analysis_complete": False},
                                     error_message="URLScan analysis did not complete within the configured timeout.")
        page = result_payload.get("page", {}); verdicts = result_payload.get("verdicts", {}).get("overall", {}); lists = result_payload.get("lists", {})
        return IntegrationResult(source=self.source_name, status=ModuleResultStatus.SUCCESS, data={
            "url": target, "scan_uuid": scan_uuid, "analysis_complete": True, "final_url": page.get("url"),
            "page_title": page.get("title"), "resolved_ip": page.get("ip"), "resolved_country": page.get("country"),
            "server": page.get("server"), "malicious": bool(verdicts.get("malicious", False)),
            "verdict_score": verdicts.get("score"), "verdict_categories": verdicts.get("categories", []),
            "related_ips": lists.get("ips", []), "related_domains": lists.get("domains", []),
        })

    async def _poll_for_result(self, client: httpx.AsyncClient, result_api_url: str) -> dict | None:
        elapsed = 0.0
        while elapsed < settings.URLSCAN_POLL_TIMEOUT_SECONDS:
            try:
                response = await request_with_retry(client, "GET", result_api_url, max_retries=0)
            except IntegrationTimeoutError:
                response = None
            if response is not None and response.status_code == 200:
                return response.json()
            await asyncio.sleep(settings.URLSCAN_POLL_INTERVAL_SECONDS)
            elapsed += settings.URLSCAN_POLL_INTERVAL_SECONDS
        return None
