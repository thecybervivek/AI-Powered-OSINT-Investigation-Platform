import hashlib

import httpx

from backend.app.core.config import settings
from backend.app.integrations.base import AsyncBaseIntegration
from backend.app.integrations.base import IntegrationResult
from backend.app.models.investigation import ModuleResultStatus
from backend.app.utils.http_client import request_with_retry


class GravatarIntegration(AsyncBaseIntegration):
    """
    Gravatar publicly links an MD5 hash of a lower-cased, trimmed email
    address to an avatar/profile. A 200 on the profile JSON endpoint
    confirms a Gravatar account is registered to the address; a 404
    means none exists. No API key required.
    """

    source_name = "gravatar"

    def is_configured(self) -> bool:
        return True

    async def _query(self, target: str) -> IntegrationResult:

        normalized = target.strip().lower()
        email_hash = hashlib.md5(normalized.encode("utf-8")).hexdigest()

        profile_url = f"{settings.GRAVATAR_BASE_URL}/{email_hash}.json"
        avatar_url = f"{settings.GRAVATAR_BASE_URL}/avatar/{email_hash}?d=404"

        async with httpx.AsyncClient(timeout=settings.OSINT_REQUEST_TIMEOUT_SECONDS) as client:

            response = await request_with_retry(client, "GET", profile_url)

        if response.status_code == 404:

            return IntegrationResult(
                source=self.source_name,
                status=ModuleResultStatus.NOT_FOUND,
                data={
                    "email_hash": email_hash,
                    "has_profile": False,
                    "avatar_url": None,
                },
            )

        if response.status_code != 200:

            return IntegrationResult(
                source=self.source_name,
                status=ModuleResultStatus.FAILED,
                error_message=f"Gravatar returned HTTP {response.status_code}.",
            )

        payload = response.json()
        entries = payload.get("entry", [])
        profile = entries[0] if entries else {}

        data = {
            "email_hash": email_hash,
            "has_profile": True,
            "display_name": profile.get("displayName"),
            "profile_url": profile.get("profileUrl"),
            "avatar_url": avatar_url,
            "location": profile.get("currentLocation"),
            "accounts": [
                {
                    "domain": account.get("domain"),
                    "url": account.get("url"),
                }
                for account in profile.get("accounts", [])
            ],
        }

        return IntegrationResult(
            source=self.source_name,
            status=ModuleResultStatus.SUCCESS,
            data=data,
        )
