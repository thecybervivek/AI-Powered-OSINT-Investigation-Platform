"""
SoundCloud email account-presence checker.

SoundCloud's identifier-availability endpoint reports whether an email
is already in use during sign-up:
GET /web-auth/identifier?q=<email> -> {"status": "in_use" | "available" | ...}.
Publicly reachable, unauthenticated - the same endpoint SoundCloud's
own sign-up form calls while a visitor types their email.
"""

import time

import httpx

from backend.app.integrations.email.base_checker import AccountPresenceState
from backend.app.integrations.email.base_checker import PlatformCheckResult
from backend.app.integrations.email.base_checker import PresencePlatform
from backend.app.integrations.email.base_checker import make_result
from backend.app.integrations.exceptions import IntegrationTimeoutError
from backend.app.utils.http_client import assert_public_url
from backend.app.utils.http_client import request_with_retry


async def _check_soundcloud(client: httpx.AsyncClient, email: str) -> PlatformCheckResult:

    platform = SOUNDCLOUD
    start = time.perf_counter()
    url = f"https://api-auth.soundcloud.com/web-auth/identifier?q={email}"

    try:
        assert_public_url(url)

        response = await request_with_retry(client, "GET", url, max_retries=0)

        if response.status_code == 429:
            return make_result(
                platform, AccountPresenceState.RATE_LIMITED,
                "SoundCloud rate-limited the identifier check.",
                http_status=response.status_code, start=start,
                provider_reason="HTTP 429 from web-auth/identifier.",
            )

        if response.status_code != 200:
            return make_result(
                platform, AccountPresenceState.UNKNOWN,
                f"Unexpected HTTP {response.status_code} from web-auth/identifier.",
                http_status=response.status_code, start=start,
            )

        try:
            payload = response.json()
        except ValueError:
            return make_result(
                platform, AccountPresenceState.UNKNOWN,
                "Response body was not valid JSON.",
                http_status=response.status_code, start=start,
            )

        api_status = payload.get("status")

        if api_status == "in_use":
            return make_result(
                platform, AccountPresenceState.CONFIRMED,
                "SoundCloud's identifier endpoint returned status=\"in_use\".",
                http_status=response.status_code, start=start,
            )

        if api_status == "available":
            return make_result(
                platform, AccountPresenceState.NOT_FOUND,
                "SoundCloud's identifier endpoint returned status=\"available\".",
                http_status=response.status_code, start=start,
            )

        return make_result(
            platform, AccountPresenceState.UNKNOWN,
            f"Unrecognized status value from identifier endpoint: {api_status!r}.",
            http_status=response.status_code, start=start,
        )

    except (IntegrationTimeoutError, httpx.ConnectError, httpx.RemoteProtocolError) as error:
        return make_result(
            platform, AccountPresenceState.FAILED,
            f"Network error before a response was received: {error.__class__.__name__}.",
            http_status=None, start=start,
            provider_reason=f"Network error: {error.__class__.__name__}",
        )

    except ValueError as error:
        return make_result(
            platform, AccountPresenceState.FAILED,
            str(error), http_status=None, start=start, provider_reason=str(error),
        )


SOUNDCLOUD = PresencePlatform(
    name="soundcloud", domain="soundcloud.com", category="entertainment", checker=_check_soundcloud,
)
