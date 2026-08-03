import ipaddress

import httpx

from backend.app.core.config import settings
from backend.app.integrations.base import AsyncBaseIntegration
from backend.app.integrations.base import IntegrationResult
from backend.app.integrations.exceptions import IntegrationAuthError
from backend.app.integrations.exceptions import IntegrationRateLimitError
from backend.app.integrations.virustotal_common import extract_flagged_vendors
from backend.app.integrations.virustotal_common import summarize_analysis_stats
from backend.app.models.investigation import ModuleResultStatus
from backend.app.utils.http_client import request_with_retry


class VirusTotalIPIntegration(AsyncBaseIntegration):
    """
    Queries VirusTotal's `/ip_addresses/{ip}` endpoint, which aggregates
    verdicts from ~70 antivirus/security vendors plus VT's own
    reputation score, ASN ownership, and community tags for the IP.

    Optional integration: requires VIRUSTOTAL_API_KEY. Reports
    status=skipped with a clear message when the key is absent.
    """

    source_name = "virustotal_ip"

    def is_configured(self) -> bool:
        return bool(settings.VIRUSTOTAL_API_KEY)

    async def _query(self, target: str) -> IntegrationResult:

        try:
            ipaddress.ip_address(target)

        except ValueError:

            return IntegrationResult(
                source=self.source_name,
                status=ModuleResultStatus.FAILED,
                error_message=f"'{target}' is not a valid IP address.",
            )

        url = f"{settings.VIRUSTOTAL_BASE_URL}/ip_addresses/{target}"
        headers = {"x-apikey": settings.VIRUSTOTAL_API_KEY}

        async with httpx.AsyncClient(timeout=settings.OSINT_REQUEST_TIMEOUT_SECONDS) as client:

            response = await request_with_retry(client, "GET", url, headers=headers)

        if response.status_code == 401:
            raise IntegrationAuthError("VirusTotal rejected the configured API key.")

        if response.status_code == 429:
            raise IntegrationRateLimitError("VirusTotal rate limit exceeded.")

        if response.status_code == 404:

            return IntegrationResult(
                source=self.source_name,
                status=ModuleResultStatus.NOT_FOUND,
                data={"ip_address": target, "known_to_virustotal": False},
            )

        if response.status_code != 200:

            return IntegrationResult(
                source=self.source_name,
                status=ModuleResultStatus.FAILED,
                error_message=f"VirusTotal returned HTTP {response.status_code}.",
            )

        attributes = response.json().get("data", {}).get("attributes", {})

        stats = summarize_analysis_stats(attributes.get("last_analysis_stats", {}))
        flagged_vendors = extract_flagged_vendors(attributes.get("last_analysis_results", {}))

        data = {
            "ip_address": target,
            "known_to_virustotal": True,
            "reputation_score": attributes.get("reputation"),
            "as_owner": attributes.get("as_owner"),
            "asn": attributes.get("asn"),
            "country": attributes.get("country"),
            "tags": attributes.get("tags", []),
            "analysis_stats": stats,
            "flagged_vendors": flagged_vendors,
            "summary": _format_virustotal_summary(stats),
        }

        return IntegrationResult(
            source=self.source_name,
            status=ModuleResultStatus.SUCCESS,
            data=data,
        )


def _format_virustotal_summary(stats: dict) -> str:

    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)

    if malicious:
        return f"{malicious} vendor(s) flagged this IP as malicious."

    if suspicious:
        return f"{suspicious} vendor(s) flagged this IP as suspicious."

    return "No vendors flagged this IP as malicious or suspicious."
