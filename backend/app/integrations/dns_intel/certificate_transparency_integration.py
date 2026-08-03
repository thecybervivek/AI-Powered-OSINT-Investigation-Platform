import asyncio
import json

import httpx

from backend.app.core.config import settings
from backend.app.integrations.base import AsyncBaseIntegration
from backend.app.integrations.base import IntegrationResult
from backend.app.integrations.exceptions import IntegrationRateLimitError
from backend.app.models.investigation import ModuleResultStatus
from backend.app.utils.http_client import request_with_retry


class CertificateTransparencyIntegration(AsyncBaseIntegration):
    """
    Searches crt.sh - a free public database that mirrors Certificate
    Transparency logs from every participating CA - for every
    certificate ever issued covering *.{domain}. This is a completely
    passive technique: it reads a public log of certificates that
    already exist, never touches the target itself, and is the
    standard free source subdomain-enumeration tools (subfinder, amass,
    etc.) use for exactly this purpose.

    Each certificate's "not_before" date also gives a rough timeline of
    when a subdomain first appeared in the wild, which doubles as a
    lightweight historical-intelligence signal alongside SecurityTrails.

    Always enabled - crt.sh needs no API key.
    """

    source_name = "certificate_transparency"

    def is_configured(self) -> bool:
        return True

    async def _query(self, target: str) -> IntegrationResult:

        domain = target.strip().lower()
        url = f"{settings.CRT_SH_BASE_URL}/"
        params = {"q": f"%.{domain}", "output": "json"}

        # crt.sh is a free, best-effort public mirror and is known to
        # return transient 5xx responses under load. request_with_retry
        # already retries connection-level failures (timeouts, connect
        # errors) - this adds a small local retry specifically for HTTP
        # error status codes, scoped to this integration only, rather
        # than changing the shared retry policy for every integration.
        max_attempts = 3
        response = None

        async with httpx.AsyncClient(timeout=settings.CRT_SH_TIMEOUT_SECONDS) as client:

            for attempt in range(max_attempts):

                response = await request_with_retry(client, "GET", url, params=params)

                if response.status_code == 429:
                    raise IntegrationRateLimitError("crt.sh rate limit exceeded.")

                if response.status_code < 500:
                    break

                if attempt < max_attempts - 1:
                    await asyncio.sleep(0.5 * (attempt + 1))

        if response is None or response.status_code >= 500:

            return IntegrationResult(
                source=self.source_name,
                status=ModuleResultStatus.FAILED,
                error_message="Certificate Transparency temporarily unavailable.",
            )

        if response.status_code != 200:

            return IntegrationResult(
                source=self.source_name,
                status=ModuleResultStatus.FAILED,
                error_message=f"crt.sh returned HTTP {response.status_code}.",
            )

        certificates = _parse_crtsh_response(response.text)

        if not certificates:

            return IntegrationResult(
                source=self.source_name,
                status=ModuleResultStatus.NOT_FOUND,
                data={"domain": domain, "subdomains": [], "certificate_count": 0},
            )

        subdomains: set[str] = set()
        earliest_seen: dict[str, str] = {}

        for cert in certificates:

            names = (cert.get("name_value") or "").split("\n")

            for name in names:

                name = name.strip().lower().lstrip("*.")

                if not name or not name.endswith(domain):
                    continue

                subdomains.add(name)

                not_before = cert.get("not_before")

                if not_before and (
                    name not in earliest_seen or not_before < earliest_seen[name]
                ):
                    earliest_seen[name] = not_before

        sorted_subdomains = sorted(subdomains)

        data = {
            "domain": domain,
            "certificate_count": len(certificates),
            "subdomain_count": len(sorted_subdomains),
            "subdomains": sorted_subdomains[:500],  # cap stored payload size
            "first_seen_by_subdomain": {
                name: earliest_seen[name]
                for name in sorted_subdomains[:500]
                if name in earliest_seen
            },
        }

        return IntegrationResult(
            source=self.source_name,
            status=ModuleResultStatus.SUCCESS,
            data=data,
        )


def _parse_crtsh_response(raw_text: str) -> list[dict]:
    """
    crt.sh's JSON endpoint is well-formed in the vast majority of
    responses, but is documented (see crt.sh's own community tooling)
    to occasionally emit back-to-back objects without a separating
    comma under load - this defensively repairs that one known quirk
    rather than failing the whole lookup over a formatting glitch.
    """

    try:
        return json.loads(raw_text)

    except json.JSONDecodeError:

        try:
            repaired = "[{}]".format(raw_text.replace("}{", "},{"))
            return json.loads(repaired)

        except json.JSONDecodeError:
            return []
