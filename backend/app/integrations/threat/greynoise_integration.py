import httpx

from backend.app.core.config import settings
from backend.app.integrations.base import AsyncBaseIntegration
from backend.app.integrations.base import IntegrationResult
from backend.app.integrations.exceptions import IntegrationAuthError
from backend.app.integrations.exceptions import IntegrationRateLimitError
from backend.app.models.investigation import ModuleResultStatus
from backend.app.utils.http_client import request_with_retry


class GreyNoiseIntegration(AsyncBaseIntegration):
    """
    Queries GreyNoise's free Community API for the target IP. GreyNoise
    specializes in one question that neither Shodan/Censys nor generic
    reputation feeds answer well: is this IP part of routine, internet-
    wide scanning "noise" (research scanners, worms, mass vulnerability
    scanners) rather than a targeted actor - and separately, is it a
    well-known benign business service (RIOT, e.g. a Google/Cloudflare
    endpoint) that would otherwise look suspicious out of context.

    Optional: requires GREYNOISE_API_KEY (a free Community API key).
    """

    source_name = "greynoise"

    def is_configured(self) -> bool:
        return bool(settings.GREYNOISE_API_KEY)

    async def _query(self, target: str) -> IntegrationResult:

        url = f"{settings.GREYNOISE_BASE_URL}/{target}"
        headers = {"key": settings.GREYNOISE_API_KEY, "Accept": "application/json"}

        async with httpx.AsyncClient(timeout=settings.OSINT_REQUEST_TIMEOUT_SECONDS) as client:

            response = await request_with_retry(client, "GET", url, headers=headers)

        if response.status_code == 401:
            raise IntegrationAuthError("GreyNoise rejected the configured API key.")

        if response.status_code == 429:
            raise IntegrationRateLimitError("GreyNoise rate limit exceeded.")

        if response.status_code != 200:

            return IntegrationResult(
                source=self.source_name,
                status=ModuleResultStatus.FAILED,
                error_message=f"GreyNoise returned HTTP {response.status_code}.",
            )

        payload = response.json()

        # GreyNoise returns 200 with a "noise"/"riot": false, empty
        # classification for IPs it has no data on at all - treat that
        # as NOT_FOUND rather than a hollow SUCCESS.
        if not payload.get("noise") and not payload.get("riot"):

            return IntegrationResult(
                source=self.source_name,
                status=ModuleResultStatus.NOT_FOUND,
                data={"ip_address": target, "classification": "unknown"},
            )

        data = {
            "ip_address": payload.get("ip", target),
            "is_internet_noise": bool(payload.get("noise")),
            "is_common_business_service": bool(payload.get("riot")),
            "classification": payload.get("classification", "unknown"),
            "actor_or_scanner_name": payload.get("name"),
            "last_seen": payload.get("last_seen"),
            "message": payload.get("message"),
        }

        return IntegrationResult(
            source=self.source_name,
            status=ModuleResultStatus.SUCCESS,
            data=data,
        )
