import httpx

from backend.app.core.config import settings
from backend.app.integrations.base import AsyncBaseIntegration
from backend.app.integrations.base import IntegrationResult
from backend.app.integrations.exceptions import IntegrationRateLimitError
from backend.app.models.investigation import ModuleResultStatus
from backend.app.utils.http_client import request_with_retry


class EmailRepIntegration(AsyncBaseIntegration):
    """
    Queries emailrep.io for reputation signals: known malicious activity,
    suspicious/spam association, and account presence heuristics. Works
    unauthenticated at a lower rate limit; an API key raises the limit.
    """

    source_name = "emailrep"

    def is_configured(self) -> bool:
        # emailrep.io supports unauthenticated lookups, so this source is
        # always usable — the key (if present) only raises the rate limit.
        return True

    async def _query(self, target: str) -> IntegrationResult:

        url = f"{settings.EMAILREP_BASE_URL}/{target}"
        headers = {}

        if settings.EMAILREP_API_KEY:
            headers["Key"] = settings.EMAILREP_API_KEY

        async with httpx.AsyncClient(timeout=settings.OSINT_REQUEST_TIMEOUT_SECONDS) as client:

            response = await request_with_retry(
                client,
                "GET",
                url,
                headers=headers,
            )

        if response.status_code == 429:
            raise IntegrationRateLimitError("EmailRep rate limit exceeded.")

        if response.status_code == 401:

            return IntegrationResult(
                source=self.source_name,
                status=ModuleResultStatus.FAILED,
                error_message="EmailRep rejected the configured API key.",
            )

        if response.status_code == 404:

            return IntegrationResult(
                source=self.source_name,
                status=ModuleResultStatus.NOT_FOUND,
                data={"email": target, "found": False},
            )

        if response.status_code != 200:

            return IntegrationResult(
                source=self.source_name,
                status=ModuleResultStatus.FAILED,
                error_message=f"EmailRep returned HTTP {response.status_code}.",
            )

        payload = response.json()
        details = payload.get("details", {})

        data = {
            "email": target,
            "reputation": payload.get("reputation"),
            "suspicious": payload.get("suspicious"),
            "references": payload.get("references"),
            "blacklisted": details.get("blacklisted"),
            "malicious_activity": details.get("malicious_activity"),
            "malicious_activity_recent": details.get("malicious_activity_recent"),
            "credentials_leaked": details.get("credentials_leaked"),
            "credentials_leaked_recent": details.get("credentials_leaked_recent"),
            "data_breach": details.get("data_breach"),
            "spam": details.get("spam"),
            "free_provider": details.get("free_provider"),
            "disposable": details.get("disposable"),
            "deliverable": details.get("deliverable"),
            "first_seen": details.get("first_seen"),
            "last_seen": details.get("last_seen"),
            "domain_exists": details.get("domain_exists"),
            "domain_reputation": details.get("domain_reputation"),
            "new_domain": details.get("new_domain"),
            "days_since_domain_creation": details.get("days_since_domain_creation"),
        }

        return IntegrationResult(
            source=self.source_name,
            status=ModuleResultStatus.SUCCESS,
            data=data,
            raw_response=payload,
        )
