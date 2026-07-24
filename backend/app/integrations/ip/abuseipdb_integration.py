import ipaddress

import httpx

from backend.app.core.config import settings
from backend.app.integrations.base import AsyncBaseIntegration
from backend.app.integrations.base import IntegrationResult
from backend.app.integrations.exceptions import IntegrationAuthError
from backend.app.integrations.exceptions import IntegrationRateLimitError
from backend.app.models.investigation import ModuleResultStatus
from backend.app.utils.http_client import request_with_retry


class AbuseIPDBIntegration(AsyncBaseIntegration):
    """
    Queries AbuseIPDB's `/check` endpoint for a target IP address.

    AbuseIPDB is a crowd-sourced database: network operators worldwide
    report IPs involved in brute-forcing, port scanning, spam, and other
    abuse. The response's `abuseConfidenceScore` (0-100) reflects how
    confident AbuseIPDB is that the IP is currently malicious, based on
    the volume/recency/diversity of those reports.

    Optional integration: requires ABUSEIPDB_API_KEY. Without it,
    AsyncBaseIntegration.run() reports status=skipped automatically via
    is_configured() below, with a clear explanatory message - the
    platform keeps working without this source.
    """

    source_name = "abuseipdb"

    def is_configured(self) -> bool:
        return bool(settings.ABUSEIPDB_API_KEY)

    async def _query(self, target: str) -> IntegrationResult:

        try:
            ipaddress.ip_address(target)

        except ValueError:

            return IntegrationResult(
                source=self.source_name,
                status=ModuleResultStatus.FAILED,
                error_message=f"'{target}' is not a valid IP address.",
            )

        url = f"{settings.ABUSEIPDB_BASE_URL}/check"

        headers = {
            "Key": settings.ABUSEIPDB_API_KEY,
            "Accept": "application/json",
        }

        params = {
            "ipAddress": target,
            "maxAgeInDays": settings.ABUSEIPDB_MAX_AGE_DAYS,
            "verbose": "true",
        }

        async with httpx.AsyncClient(timeout=settings.OSINT_REQUEST_TIMEOUT_SECONDS) as client:

            response = await request_with_retry(
                client,
                "GET",
                url,
                headers=headers,
                params=params,
            )

        if response.status_code == 401:
            raise IntegrationAuthError("AbuseIPDB rejected the configured API key.")

        if response.status_code == 429:
            raise IntegrationRateLimitError("AbuseIPDB rate limit exceeded.")

        if response.status_code != 200:

            return IntegrationResult(
                source=self.source_name,
                status=ModuleResultStatus.FAILED,
                error_message=f"AbuseIPDB returned HTTP {response.status_code}.",
            )

        payload = response.json().get("data", {})

        reports = payload.get("reports", []) or []

        recent_categories: set[int] = set()

        for report in reports:
            recent_categories.update(report.get("categories", []))

        data = {
            "ip_address": payload.get("ipAddress", target),
            "is_public": payload.get("isPublic"),
            "ip_version": payload.get("ipVersion"),
            "is_whitelisted": payload.get("isWhitelisted"),
            "abuse_confidence_score": payload.get("abuseConfidenceScore", 0),
            "country_code": payload.get("countryCode"),
            "usage_type": payload.get("usageType"),
            "isp": payload.get("isp"),
            "domain": payload.get("domain"),
            "hostnames": payload.get("hostnames", []),
            "total_reports": payload.get("totalReports", 0),
            "num_distinct_reporters": payload.get("numDistinctUsers", 0),
            "last_reported_at": payload.get("lastReportedAt"),
            "reported_category_ids": sorted(recent_categories),
        }

        return IntegrationResult(
            source=self.source_name,
            status=ModuleResultStatus.SUCCESS,
            data=data,
        )
