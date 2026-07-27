import httpx

from backend.app.core.config import settings
from backend.app.integrations.base import AsyncBaseIntegration
from backend.app.integrations.base import IntegrationResult
from backend.app.integrations.exceptions import IntegrationAuthError
from backend.app.integrations.exceptions import IntegrationRateLimitError
from backend.app.models.investigation import ModuleResultStatus
from backend.app.utils.http_client import request_with_retry


class NumVerifyIntegration(AsyncBaseIntegration):
    """
    Cross-verifies a phone number against NumVerify's real-time carrier
    and line-type database. libphonenumber's PhoneValidationIntegration
    above is fully offline and therefore always stale for numbers that
    have been ported between carriers since its bundled data was built;
    NumVerify supplements that with a live lookup.

    Optional integration: requires NUMVERIFY_API_KEY. Reports
    status=skipped with a clear message when the key is absent, exactly
    like every other optional source in this platform (AbuseIPDB,
    VirusTotal, URLScan, HIBP, MalwareBazaar, Hybrid Analysis).
    """

    source_name = "numverify"

    def is_configured(self) -> bool:
        return bool(settings.NUMVERIFY_API_KEY)

    async def _query(self, target: str) -> IntegrationResult:

        params = {
            "access_key": settings.NUMVERIFY_API_KEY,
            "number": target,
            "format": 1,
        }

        async with httpx.AsyncClient(timeout=settings.OSINT_REQUEST_TIMEOUT_SECONDS) as client:

            response = await request_with_retry(
                client,
                "GET",
                settings.NUMVERIFY_BASE_URL,
                params=params,
            )

        if response.status_code != 200:

            return IntegrationResult(
                source=self.source_name,
                status=ModuleResultStatus.FAILED,
                error_message=f"NumVerify returned HTTP {response.status_code}.",
            )

        payload = response.json()

        # NumVerify returns HTTP 200 even for auth/quota errors, with the
        # failure nested under "error" instead.
        error = payload.get("error")

        if error:

            error_code = error.get("code")

            if error_code in (101, 102, 103):
                raise IntegrationAuthError(
                    f"NumVerify rejected the configured API key: {error.get('info')}"
                )

            if error_code == 104:
                raise IntegrationRateLimitError(
                    "NumVerify monthly quota exceeded."
                )

            return IntegrationResult(
                source=self.source_name,
                status=ModuleResultStatus.FAILED,
                error_message=f"NumVerify error: {error.get('info', error_code)}",
            )

        if not payload.get("valid"):

            return IntegrationResult(
                source=self.source_name,
                status=ModuleResultStatus.NOT_FOUND,
                data={"raw_input": target, "valid": False},
            )

        data = {
            "raw_input": target,
            "valid": True,
            "number": payload.get("number"),
            "local_format": payload.get("local_format"),
            "international_format": payload.get("international_format"),
            "country_prefix": payload.get("country_prefix"),
            "country_code": payload.get("country_code"),
            "country_name": payload.get("country_name"),
            "location": payload.get("location"),
            "carrier": payload.get("carrier"),
            "line_type": payload.get("line_type"),
        }

        return IntegrationResult(
            source=self.source_name,
            status=ModuleResultStatus.SUCCESS,
            data=data,
        )
