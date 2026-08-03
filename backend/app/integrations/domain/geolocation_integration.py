import httpx

from backend.app.core.config import settings
from backend.app.integrations.base import AsyncBaseIntegration
from backend.app.integrations.base import IntegrationResult
from backend.app.integrations.domain._resolve import resolve_to_ip
from backend.app.models.investigation import ModuleResultStatus
from backend.app.utils.http_client import request_with_retry


class IPGeolocationIntegration(AsyncBaseIntegration):
    """
    Resolves the target (domain or IP) to an IP address and looks up
    coarse geolocation (country/region/city), ISP/org, and timezone via
    ip-api.com's free JSON endpoint.
    """

    source_name = "ip_geolocation"

    def is_configured(self) -> bool:
        return True

    async def _query(self, target: str) -> IntegrationResult:

        ip = await resolve_to_ip(target)

        if ip is None:

            return IntegrationResult(
                source=self.source_name,
                status=ModuleResultStatus.FAILED,
                error_message=f"Could not resolve '{target}' to an IP address.",
            )

        url = (
            f"{settings.IP_GEOLOCATION_BASE_URL}/{ip}"
            "?fields=status,message,country,countryCode,region,regionName,"
            "city,zip,lat,lon,timezone,isp,org,as,asname,query"
        )

        async with httpx.AsyncClient(timeout=settings.OSINT_REQUEST_TIMEOUT_SECONDS) as client:
            response = await request_with_retry(client, "GET", url)

        if response.status_code != 200:

            return IntegrationResult(
                source=self.source_name,
                status=ModuleResultStatus.FAILED,
                error_message=f"Geolocation provider returned HTTP {response.status_code}.",
            )

        payload = response.json()

        if payload.get("status") != "success":

            return IntegrationResult(
                source=self.source_name,
                status=ModuleResultStatus.NOT_FOUND,
                data={"ip_address": ip, "resolved_target": target},
                error_message=payload.get("message", "Geolocation lookup failed."),
            )

        data = {
            "resolved_target": target,
            "ip_address": payload.get("query", ip),
            "country": payload.get("country"),
            "country_code": payload.get("countryCode"),
            "region": payload.get("regionName"),
            "city": payload.get("city"),
            "postal_code": payload.get("zip"),
            "latitude": payload.get("lat"),
            "longitude": payload.get("lon"),
            "timezone": payload.get("timezone"),
            "isp": payload.get("isp"),
            "organization": payload.get("org"),
            "asn": payload.get("as"),
            "asn_name": payload.get("asname"),
            "summary": _format_geolocation_summary(
                payload.get("city"), payload.get("regionName"), payload.get("country"),
            ),
        }

        return IntegrationResult(
            source=self.source_name,
            status=ModuleResultStatus.SUCCESS,
            data=data,
        )


def _format_geolocation_summary(city: str | None, region: str | None, country: str | None) -> str:

    parts = [p for p in (city, region, country) if p]

    return ", ".join(parts) if parts else "Location could not be determined."
