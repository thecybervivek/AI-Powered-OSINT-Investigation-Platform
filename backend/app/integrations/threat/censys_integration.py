import httpx

from backend.app.core.config import settings
from backend.app.integrations.base import AsyncBaseIntegration
from backend.app.integrations.base import IntegrationResult
from backend.app.integrations.exceptions import IntegrationAuthError
from backend.app.integrations.exceptions import IntegrationRateLimitError
from backend.app.models.investigation import ModuleResultStatus
from backend.app.utils.http_client import request_with_retry


class CensysIntegration(AsyncBaseIntegration):
    """
    Queries Censys's v2 hosts endpoint for the target IP: detected
    services per port, autonomous system (ASN/organization), and
    Censys's own labels. An independent internet-wide scan dataset from
    Shodan's - the two frequently see different snapshots of the same
    host, so both are run rather than treating either as authoritative.

    Optional: requires both CENSYS_API_ID and CENSYS_API_SECRET
    (Censys v2 authenticates with HTTP Basic Auth using these as
    username/password, not a single bearer token).
    """

    source_name = "censys"

    def is_configured(self) -> bool:
        return bool(settings.CENSYS_API_ID and settings.CENSYS_API_SECRET)

    async def _query(self, target: str) -> IntegrationResult:

        url = f"{settings.CENSYS_BASE_URL}/hosts/{target}"

        async with httpx.AsyncClient(timeout=settings.OSINT_REQUEST_TIMEOUT_SECONDS) as client:

            response = await request_with_retry(
                client,
                "GET",
                url,
                auth=(settings.CENSYS_API_ID, settings.CENSYS_API_SECRET),
            )

        if response.status_code == 401 or response.status_code == 403:
            raise IntegrationAuthError(
                "Censys rejected the configured API ID/Secret."
            )

        if response.status_code == 429:
            raise IntegrationRateLimitError("Censys rate limit exceeded.")

        if response.status_code == 404:

            return IntegrationResult(
                source=self.source_name,
                status=ModuleResultStatus.NOT_FOUND,
                data={"ip_address": target, "known_to_censys": False},
            )

        if response.status_code != 200:

            return IntegrationResult(
                source=self.source_name,
                status=ModuleResultStatus.FAILED,
                error_message=f"Censys returned HTTP {response.status_code}.",
            )

        result = response.json().get("result", {})
        autonomous_system = result.get("autonomous_system", {}) or {}

        services = [
            {
                "port": service.get("port"),
                "transport_protocol": service.get("transport_protocol"),
                "service_name": service.get("service_name"),
                "banner": (service.get("banner") or "")[:500],
            }
            for service in result.get("services", [])
        ]

        data = {
            "ip_address": result.get("ip", target),
            "known_to_censys": True,
            "organization": autonomous_system.get("name"),
            "asn": autonomous_system.get("asn"),
            "country": (result.get("location") or {}).get("country"),
            "open_ports": sorted(
                {s.get("port") for s in result.get("services", []) if s.get("port")}
            ),
            "services": services,
            "operating_system": (result.get("operating_system") or {}).get("product"),
            "labels": result.get("labels", []),
            "last_updated": result.get("last_updated_at"),
        }

        return IntegrationResult(
            source=self.source_name,
            status=ModuleResultStatus.SUCCESS,
            data=data,
        )
