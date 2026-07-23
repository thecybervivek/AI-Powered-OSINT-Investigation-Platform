from urllib.parse import quote

import httpx

from backend.app.core.config import settings
from backend.app.integrations.base import AsyncBaseIntegration
from backend.app.integrations.base import IntegrationResult
from backend.app.integrations.exceptions import IntegrationAuthError
from backend.app.integrations.exceptions import IntegrationRateLimitError
from backend.app.models.investigation import ModuleResultStatus
from backend.app.utils.http_client import request_with_retry


class HIBPIntegration(AsyncBaseIntegration):
    """
    Queries the HaveIBeenPwned breach database for the target email
    address. Requires an API key (HIBP_API_KEY) per HIBP's terms of
    service — the integration reports SKIPPED rather than failing when
    it isn't configured.
    """

    source_name = "hibp"

    def is_configured(self) -> bool:
        return bool(settings.HIBP_API_KEY)

    async def _query(self, target: str) -> IntegrationResult:

        encoded_email = quote(target, safe="")
        url = (
            f"{settings.HIBP_BASE_URL}/breachedaccount/{encoded_email}"
            f"?truncateResponse=false"
        )

        headers = {
            "hibp-api-key": settings.HIBP_API_KEY,
        }

        async with httpx.AsyncClient(timeout=settings.OSINT_REQUEST_TIMEOUT_SECONDS) as client:

            response = await request_with_retry(
                client,
                "GET",
                url,
                headers=headers,
            )

        if response.status_code == 401:
            raise IntegrationAuthError("HIBP rejected the configured API key.")

        if response.status_code == 429:
            raise IntegrationRateLimitError("HIBP rate limit exceeded.")

        if response.status_code == 404:

            return IntegrationResult(
                source=self.source_name,
                status=ModuleResultStatus.NOT_FOUND,
                data={
                    "email": target,
                    "breached": False,
                    "breach_count": 0,
                    "breaches": [],
                },
            )

        if response.status_code != 200:

            return IntegrationResult(
                source=self.source_name,
                status=ModuleResultStatus.FAILED,
                error_message=f"HIBP returned HTTP {response.status_code}.",
            )

        breaches = response.json()

        summarized = [
            {
                "name": breach.get("Name"),
                "domain": breach.get("Domain"),
                "breach_date": breach.get("BreachDate"),
                "added_date": breach.get("AddedDate"),
                "pwn_count": breach.get("PwnCount"),
                "data_classes": breach.get("DataClasses", []),
                "is_verified": breach.get("IsVerified"),
                "is_sensitive": breach.get("IsSensitive"),
                "is_fabricated": breach.get("IsFabricated"),
            }
            for breach in breaches
        ]

        data = {
            "email": target,
            "breached": len(summarized) > 0,
            "breach_count": len(summarized),
            "breaches": summarized,
            "contains_sensitive_breach": any(
                b["is_sensitive"] for b in summarized
            ),
        }

        return IntegrationResult(
            source=self.source_name,
            status=ModuleResultStatus.SUCCESS,
            data=data,
        )
