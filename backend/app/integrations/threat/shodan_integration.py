import httpx

from backend.app.core.config import settings
from backend.app.integrations.base import AsyncBaseIntegration
from backend.app.integrations.base import IntegrationResult
from backend.app.integrations.exceptions import IntegrationAuthError
from backend.app.integrations.exceptions import IntegrationRateLimitError
from backend.app.models.investigation import ModuleResultStatus
from backend.app.utils.http_client import request_with_retry


class ShodanIntegration(AsyncBaseIntegration):
    """
    Queries Shodan's host endpoint for the target IP: every port Shodan
    has observed open, the banner/service detected on each, the
    organization and ASN, associated hostnames, and Shodan's own tags
    (e.g. "cloud", "iot", "self-signed"). This is passive intelligence -
    it reads Shodan's existing internet-wide scan data, it never itself
    scans the target.

    Optional: requires SHODAN_API_KEY.
    """

    source_name = "shodan"

    def is_configured(self) -> bool:
        return bool(settings.SHODAN_API_KEY)

    async def _query(self, target: str) -> IntegrationResult:

        url = f"{settings.SHODAN_BASE_URL}/shodan/host/{target}"
        params = {"key": settings.SHODAN_API_KEY}

        async with httpx.AsyncClient(timeout=settings.OSINT_REQUEST_TIMEOUT_SECONDS) as client:

            response = await request_with_retry(client, "GET", url, params=params)

        if response.status_code == 401:
            raise IntegrationAuthError("Shodan rejected the configured API key.")

        if response.status_code == 429:
            raise IntegrationRateLimitError("Shodan rate limit exceeded.")

        if response.status_code == 404:

            return IntegrationResult(
                source=self.source_name,
                status=ModuleResultStatus.NOT_FOUND,
                data={"ip_address": target, "known_to_shodan": False},
            )

        if response.status_code != 200:

            return IntegrationResult(
                source=self.source_name,
                status=ModuleResultStatus.FAILED,
                error_message=f"Shodan returned HTTP {response.status_code}.",
            )

        payload = response.json()

        services = [
            {
                "port": item.get("port"),
                "transport": item.get("transport"),
                "product": item.get("product"),
                "version": item.get("version"),
                "banner": (item.get("data") or "")[:500],
            }
            for item in payload.get("data", [])
        ]

        data = {
            "ip_address": payload.get("ip_str", target),
            "known_to_shodan": True,
            "organization": payload.get("org"),
            "asn": payload.get("asn"),
            "hostnames": payload.get("hostnames", []),
            "domains": payload.get("domains", []),
            "country": payload.get("country_name"),
            "city": payload.get("city"),
            "open_ports": sorted(payload.get("ports", [])),
            "services": services,
            "tags": payload.get("tags", []),
            "last_update": payload.get("last_update"),
            "vulnerabilities": sorted(payload.get("vulns", []) or []),
        }

        return IntegrationResult(
            source=self.source_name,
            status=ModuleResultStatus.SUCCESS,
            data=data,
        )
