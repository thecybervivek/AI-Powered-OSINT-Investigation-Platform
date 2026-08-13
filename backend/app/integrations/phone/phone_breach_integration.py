import httpx

from backend.app.core.config import settings
from backend.app.integrations.base import AsyncBaseIntegration
from backend.app.integrations.base import IntegrationResult
from backend.app.integrations.exceptions import IntegrationAuthError
from backend.app.integrations.exceptions import IntegrationRateLimitError
from backend.app.models.investigation import ModuleResultStatus
from backend.app.utils.http_client import request_with_retry

# Fields DeHashed entries use to indicate a plaintext vs. hashed
# password was present. Mirrors the classification convention already
# established by integrations/breach/dehashed_integration.py, kept
# duplicated here (rather than imported) so this phone-specific
# integration has zero coupling to the standalone Breach Intelligence
# module - see phone_service.py module docstring / scope note.
_PLAINTEXT_FIELD = "password"
_HASHED_FIELD = "hashed_password"


class PhoneBreachIntegration(AsyncBaseIntegration):
    """
    Phone Breach Intelligence layer (Phone Intelligence 2.0, section 6):
    queries DeHashed's phone-number search for exposure in known
    breach/leak datasets. Reuses the same DEHASHED_EMAIL/DEHASHED_API_KEY
    credential pair as the standalone Breach Intelligence module
    (Milestone 9 Part 4) - same account, different query shape - but is
    implemented independently of integrations/breach/dehashed_integration.py
    so this phone-specific addition can never regress that module.

    Never exposes plaintext passwords, password hashes, auth tokens,
    session cookies, API keys, or other secrets - only whether they were
    present (has_plaintext_password_exposure / has_hashed_password_exposure),
    exactly like the standalone module's own redaction policy.

    Optional integration: SKIPPED when DeHashed isn't configured, exactly
    like every other optional source in this platform.
    """

    source_name = "phone_breach"

    def is_configured(self) -> bool:
        return bool(settings.DEHASHED_EMAIL and settings.DEHASHED_API_KEY)

    async def _query(self, target: str) -> IntegrationResult:

        query = f"phone_number:{target}"

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

        breached_databases = sorted(
            {e["database_name"] for e in entries if e.get("database_name")}
        )

        has_plaintext = any(e.get(_PLAINTEXT_FIELD) for e in entries)
        has_hashed_only = (
            not has_plaintext
            and any(e.get(_HASHED_FIELD) for e in entries)
        )

        # Redacted, capped view - never the raw secret fields themselves.
        redacted_entries = [
            {
                "database_name": e.get("database_name"),
                "phone": e.get("phone"),
                "email": e.get("email"),
                "username": e.get("username"),
                "name": e.get("name"),
                "address": e.get("address"),
                "has_plaintext_password": bool(e.get(_PLAINTEXT_FIELD)),
                "has_hashed_password": bool(e.get(_HASHED_FIELD)),
            }
            for e in entries
        ]

        data = {
            "query": query,
            "total_entries": len(entries),
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
