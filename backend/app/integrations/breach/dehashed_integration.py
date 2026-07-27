import httpx

from backend.app.core.config import settings
from backend.app.integrations.base import AsyncBaseIntegration
from backend.app.integrations.base import IntegrationResult
from backend.app.integrations.exceptions import IntegrationAuthError
from backend.app.integrations.exceptions import IntegrationRateLimitError
from backend.app.models.investigation import ModuleResultStatus
from backend.app.utils.http_client import request_with_retry

# Recognized DeHashed field names that indicate a plaintext password was
# present in the breached record, vs. only a hash. Field naming isn't
# perfectly standardized across DeHashed's data wells, so this is a
# best-effort classification of what "password_exposure_status" reports.
_PLAINTEXT_FIELD = "password"
_HASHED_FIELD = "hashed_password"


class DeHashedIntegration(AsyncBaseIntegration):
    """
    Queries the DeHashed breach-search API for the target email or
    domain. DeHashed indexes a very large set of breach/leak datasets
    and, unlike HIBP's public tier, supports domain-wide search
    (query=domain:example.com returns every breached account DeHashed
    has on that domain) alongside per-email lookups.

    Optional integration: requires both DEHASHED_EMAIL and
    DEHASHED_API_KEY (their API authenticates with HTTP Basic Auth using
    the account email as the username and the API key as the password -
    the pattern documented across DeHashed's own client examples).
    Reports status=skipped with a clear message when not configured.

    NOTE ON API STABILITY: DeHashed's public documentation
    (app.dehashed.com/documentation/api) sits behind an account login,
    so this integration is built from DeHashed's own published tooling
    conventions and third-party client examples rather than a directly
    fetched spec page. If DeHashed changes their auth scheme or
    response shape, only this one file needs updating - nothing else in
    the breach module depends on DeHashed's wire format.
    """

    source_name = "dehashed"

    def is_configured(self) -> bool:
        return bool(settings.DEHASHED_EMAIL and settings.DEHASHED_API_KEY)

    async def _query(self, target: str) -> IntegrationResult:

        query = f"email:{target}" if "@" in target else f"domain:{target}"

        url = f"{settings.DEHASHED_BASE_URL}/search"
        params = {"query": query}
        headers = {"Accept": "application/json"}

        async with httpx.AsyncClient(timeout=settings.OSINT_REQUEST_TIMEOUT_SECONDS) as client:

            response = await request_with_retry(
                client,
                "GET",
                url,
                headers=headers,
                params=params,
                auth=(settings.DEHASHED_EMAIL, settings.DEHASHED_API_KEY),
            )

        if response.status_code == 401:
            raise IntegrationAuthError(
                "DeHashed rejected the configured email/API key."
            )

        if response.status_code == 429:
            raise IntegrationRateLimitError("DeHashed rate limit exceeded.")

        if response.status_code != 200:

            return IntegrationResult(
                source=self.source_name,
                status=ModuleResultStatus.FAILED,
                error_message=f"DeHashed returned HTTP {response.status_code}.",
            )

        payload = response.json()
        entries = payload.get("entries") or []

        if not entries:

            return IntegrationResult(
                source=self.source_name,
                status=ModuleResultStatus.NOT_FOUND,
                data={"query": query, "total_entries": 0, "entries": []},
            )

        exposed_emails = sorted(
            {e["email"] for e in entries if e.get("email")}
        )
        exposed_domains = sorted(
            {
                e["email"].rsplit("@", 1)[-1].lower()
                for e in entries
                if e.get("email") and "@" in e["email"]
            }
        )
        breached_databases = sorted(
            {e["database_name"] for e in entries if e.get("database_name")}
        )

        has_plaintext = any(e.get(_PLAINTEXT_FIELD) for e in entries)
        has_hashed_only = (
            not has_plaintext
            and any(e.get(_HASHED_FIELD) for e in entries)
        )

        # Never persist the actual password/hash values themselves -
        # only whether they were present. This module reports EXPOSURE,
        # not a copy of the leaked credential.
        redacted_entries = [
            {
                "database_name": e.get("database_name"),
                "email": e.get("email"),
                "username": e.get("username"),
                "has_plaintext_password": bool(e.get(_PLAINTEXT_FIELD)),
                "has_hashed_password": bool(e.get(_HASHED_FIELD)),
                "ip_address": e.get("ip_address"),
                "phone": e.get("phone"),
            }
            for e in entries
        ]

        data = {
            "query": query,
            "total_entries": len(entries),
            "exposed_emails": exposed_emails,
            "exposed_domains": exposed_domains,
            "breached_databases": breached_databases,
            "has_plaintext_password_exposure": has_plaintext,
            "has_hashed_password_exposure": has_hashed_only,
            "entries": redacted_entries[:50],  # cap stored payload size
        }

        return IntegrationResult(
            source=self.source_name,
            status=ModuleResultStatus.SUCCESS,
            data=data,
        )
