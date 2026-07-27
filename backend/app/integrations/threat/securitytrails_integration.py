import httpx

from backend.app.core.config import settings
from backend.app.integrations.base import AsyncBaseIntegration
from backend.app.integrations.base import IntegrationResult
from backend.app.integrations.exceptions import IntegrationAuthError
from backend.app.integrations.exceptions import IntegrationRateLimitError
from backend.app.models.investigation import ModuleResultStatus
from backend.app.utils.http_client import request_with_retry


class SecurityTrailsIntegration(AsyncBaseIntegration):
    """
    Queries SecurityTrails's historical A-record endpoint for a domain:
    every IP address the domain has resolved to over time, each with
    the window it was observed - the "Historical Intelligence"
    capability this milestone calls for, complementing Milestone 4's
    live-only DNS/WHOIS lookups (which only ever show the current
    state). Domain targets only - SecurityTrails' historical DNS is
    keyed by domain, not IP.

    Optional: requires SECURITYTRAILS_API_KEY.
    """

    source_name = "securitytrails"

    def is_configured(self) -> bool:
        return bool(settings.SECURITYTRAILS_API_KEY)

    async def _query(self, target: str) -> IntegrationResult:

        if _looks_like_ipv4(target):

            return IntegrationResult(
                source=self.source_name,
                status=ModuleResultStatus.SKIPPED,
                error_message=(
                    "SecurityTrails historical DNS is keyed by domain, "
                    "not IP; skipped for this target."
                ),
            )

        url = f"{settings.SECURITYTRAILS_BASE_URL}/history/{target}/dns/a"
        headers = {"APIKEY": settings.SECURITYTRAILS_API_KEY, "Accept": "application/json"}

        async with httpx.AsyncClient(timeout=settings.OSINT_REQUEST_TIMEOUT_SECONDS) as client:

            response = await request_with_retry(client, "GET", url, headers=headers)

        if response.status_code == 401 or response.status_code == 403:
            raise IntegrationAuthError(
                "SecurityTrails rejected the configured API key."
            )

        if response.status_code == 429:
            raise IntegrationRateLimitError("SecurityTrails rate limit exceeded.")

        if response.status_code == 404:

            return IntegrationResult(
                source=self.source_name,
                status=ModuleResultStatus.NOT_FOUND,
                data={"domain": target, "historical_records": []},
            )

        if response.status_code != 200:

            return IntegrationResult(
                source=self.source_name,
                status=ModuleResultStatus.FAILED,
                error_message=f"SecurityTrails returned HTTP {response.status_code}.",
            )

        payload = response.json()
        records = payload.get("records", []) or []

        historical_records = [
            {
                "ip_addresses": [v.get("ip") for v in record.get("values", []) if v.get("ip")],
                "first_seen": record.get("first_seen"),
                "last_seen": record.get("last_seen"),
                "organizations": sorted(
                    {v.get("organization") for v in record.get("values", []) if v.get("organization")}
                ),
            }
            for record in records
        ]

        all_ips = sorted(
            {ip for rec in historical_records for ip in rec["ip_addresses"]}
        )

        data = {
            "domain": target,
            "total_historical_records": len(historical_records),
            "distinct_ip_addresses_seen": all_ips,
            "historical_records": historical_records,
        }

        return IntegrationResult(
            source=self.source_name,
            status=ModuleResultStatus.SUCCESS,
            data=data,
        )


def _looks_like_ipv4(target: str) -> bool:

    parts = target.split(".")

    return len(parts) == 4 and all(part.isdigit() for part in parts)
