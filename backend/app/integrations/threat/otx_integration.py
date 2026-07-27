import httpx

from backend.app.core.config import settings
from backend.app.integrations.base import AsyncBaseIntegration
from backend.app.integrations.base import IntegrationResult
from backend.app.integrations.exceptions import IntegrationAuthError
from backend.app.integrations.exceptions import IntegrationRateLimitError
from backend.app.models.investigation import ModuleResultStatus
from backend.app.utils.http_client import request_with_retry


class OTXIntegration(AsyncBaseIntegration):
    """
    Queries AlienVault OTX's "general" indicator endpoint. OTX is a
    community threat-sharing platform: analysts publish "pulses" - named
    write-ups tying a set of indicators to a campaign or actor. This
    reports how many pulses reference the target and their names/tags,
    which is a community-corroboration signal (more independent pulses
    referencing an indicator suggests more confidence it's actually
    malicious infrastructure, not just a single unverified report).

    Works for IP, domain, AND file-hash targets - OTX indicator
    "sections" just change (IPv4 / domain / file), which this
    integration picks automatically based on the target's shape.
    File-hash support (Milestone 9 Part 7) reuses this same class for
    malware campaign/threat-actor correlation rather than adding a
    second OTX client.

    Optional: requires OTX_API_KEY (free registration).
    """

    source_name = "otx"

    def is_configured(self) -> bool:
        return bool(settings.OTX_API_KEY)

    async def _query(self, target: str) -> IntegrationResult:

        section = _otx_section_for(target)

        url = f"{settings.OTX_BASE_URL}/indicators/{section}/{target}/general"
        headers = {"X-OTX-API-KEY": settings.OTX_API_KEY}

        async with httpx.AsyncClient(timeout=settings.OSINT_REQUEST_TIMEOUT_SECONDS) as client:

            response = await request_with_retry(client, "GET", url, headers=headers)

        if response.status_code == 401:
            raise IntegrationAuthError("OTX rejected the configured API key.")

        if response.status_code == 429:
            raise IntegrationRateLimitError("OTX rate limit exceeded.")

        if response.status_code == 404:

            return IntegrationResult(
                source=self.source_name,
                status=ModuleResultStatus.NOT_FOUND,
                data={"indicator": target, "pulse_count": 0},
            )

        if response.status_code != 200:

            return IntegrationResult(
                source=self.source_name,
                status=ModuleResultStatus.FAILED,
                error_message=f"OTX returned HTTP {response.status_code}.",
            )

        payload = response.json()
        pulse_info = payload.get("pulse_info", {}) or {}
        pulses = pulse_info.get("pulses", []) or []

        pulse_names = sorted({p.get("name") for p in pulses if p.get("name")})
        tags = sorted({tag for p in pulses for tag in (p.get("tags") or [])})
        adversary_names = sorted(
            {p.get("adversary") for p in pulses if p.get("adversary")}
        )

        pulse_count = pulse_info.get("count", len(pulses))

        if pulse_count == 0:

            return IntegrationResult(
                source=self.source_name,
                status=ModuleResultStatus.NOT_FOUND,
                data={
                    "indicator": target,
                    "pulse_count": 0,
                    "asn": payload.get("asn"),
                    "country": payload.get("country_name"),
                },
            )

        data = {
            "indicator": target,
            "pulse_count": pulse_count,
            "pulse_names": pulse_names[:20],
            "tags": tags[:30],
            "associated_adversaries": adversary_names,
            "asn": payload.get("asn"),
            "country": payload.get("country_name"),
        }

        return IntegrationResult(
            source=self.source_name,
            status=ModuleResultStatus.SUCCESS,
            data=data,
        )


def _looks_like_ipv4(target: str) -> bool:

    parts = target.split(".")

    return len(parts) == 4 and all(part.isdigit() for part in parts)


def _looks_like_hash(target: str) -> bool:

    return len(target) in (32, 40, 64) and all(
        c in "0123456789abcdefABCDEF" for c in target
    )


def _otx_section_for(target: str) -> str:

    if _looks_like_ipv4(target):
        return "IPv4"

    if _looks_like_hash(target):
        return "file"

    return "domain"
