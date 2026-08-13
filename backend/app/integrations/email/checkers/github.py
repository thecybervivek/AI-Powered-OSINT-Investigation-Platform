"""
GitHub email account-presence checker.

GitHub's public sign-up form validates the email address against
existing accounts client-side, via POST /signup_check/email:
HTTP 422 = address already registered, HTTP 200 = available. Both are
publicly reachable, unauthenticated endpoints (this is the same page
any visitor's browser talks to while typing into the sign-up form) -
no CAPTCHA, session, or anti-bot defeat involved.
"""

import re
import time

import httpx

from backend.app.integrations.email.base_checker import AccountPresenceState
from backend.app.integrations.email.base_checker import PlatformCheckResult
from backend.app.integrations.email.base_checker import PresencePlatform
from backend.app.integrations.email.base_checker import make_result
from backend.app.integrations.exceptions import IntegrationTimeoutError
from backend.app.utils.http_client import assert_public_url
from backend.app.utils.http_client import request_with_retry


async def _check_github(client: httpx.AsyncClient, email: str) -> PlatformCheckResult:

    platform = GITHUB
    start = time.perf_counter()
    join_url = "https://github.com/join"
    check_url = "https://github.com/signup_check/email"

    try:
        assert_public_url(join_url)

        join_response = await request_with_retry(
            client, "GET", join_url, max_retries=0,
        )

        # The signup page embeds a CSRF token in an <auto-check> tag
        # pair (username check, email check) - we need the second one.
        token_match = re.search(
            r'<auto-check\s+src="/signup_check/email"[\s\S]*?'
            r'authenticity_token"\s+value="([^"]+)"',
            join_response.text,
        )

        if not token_match:
            return make_result(
                platform, AccountPresenceState.UNKNOWN,
                "Sign-up page did not contain the expected email-check form.",
                http_status=join_response.status_code, start=start,
                provider_reason="Page shape did not match (upstream page changed?).",
            )

        response = await request_with_retry(
            client, "POST", check_url, max_retries=0,
            data={"value": email, "authenticity_token": token_match.group(1)},
        )

        if response.status_code == 422:
            return make_result(
                platform, AccountPresenceState.CONFIRMED,
                "GitHub's signup_check/email endpoint returned HTTP 422 "
                "(address already registered).",
                http_status=response.status_code, start=start,
            )

        if response.status_code == 200:
            return make_result(
                platform, AccountPresenceState.NOT_FOUND,
                "GitHub's signup_check/email endpoint returned HTTP 200 "
                "(address available).",
                http_status=response.status_code, start=start,
            )

        if response.status_code == 429:
            return make_result(
                platform, AccountPresenceState.RATE_LIMITED,
                "GitHub rate-limited the signup check.",
                http_status=response.status_code, start=start,
                provider_reason="HTTP 429 from signup_check/email.",
            )

        return make_result(
            platform, AccountPresenceState.UNKNOWN,
            f"Unexpected HTTP {response.status_code} from signup_check/email.",
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


GITHUB = PresencePlatform(
    name="github", domain="github.com", category="development", checker=_check_github,
)
