"""
Email → account & social presence checking ("does this address have an
account on platform X?"), conceptually equivalent to what the username
module's base_checker.py does for handles, but probing sign-up/
password-reset flows instead of profile URLs.

Technique note: the general approach used here (submit the target
address to a platform's own public sign-up/availability endpoint and
read its response) is the same publicly documented technique used by
the open-source `holehe` project (GPLv3). No code from that project is
copied — each check below is written independently against this
codebase's own HTTP client, retry/SSRF policy, and result model — but
credit belongs to holehe's maintainers for cataloguing which platforms
expose this kind of check and how to read their responses.

Normalized result model (matches the spec exactly): platform, category,
status, confidence, evidence, http_status, profile_url, checked_at,
provider_reason.

States:

    CONFIRMED     - reliable evidence the address is registered
    NOT_FOUND     - provider gave a reliable negative result
    UNKNOWN       - provider didn't give enough evidence either way
    BLOCKED       - provider's anti-automation controls intercepted us
                    (captcha wall, WAF challenge, or a platform we've
                    deliberately never attempted to check past those
                    controls in the first place — see the BLOCKED-by-
                    design platforms below)
    RATE_LIMITED  - provider explicitly rate-limited the request
    FAILED        - the request itself didn't complete (network/timeout)

Hard rule enforced throughout this file: 401/403/429/CAPTCHA/anti-bot/
network-error responses are NEVER mapped to NOT_FOUND. A CONFIRMED/
NOT_FOUND result is only ever produced from a response that positively,
unambiguously establishes that state — never inferred from a merely
"positive-looking" status code in isolation.

Only unauthenticated, publicly-reachable endpoints are used. This file
never replays session cookies, never attempts to defeat a CAPTCHA/WAF
challenge, and never completes an actual registration/password-reset —
see BLOCKED_BY_DESIGN_PLATFORMS below for platforms where no such
legitimate signal exists today.
"""

import asyncio
import re
import time
from dataclasses import dataclass
from datetime import datetime
from datetime import timezone
from enum import Enum
from typing import Awaitable
from typing import Callable

import httpx

from backend.app.core.config import settings
from backend.app.integrations.exceptions import IntegrationTimeoutError
from backend.app.utils.http_client import assert_public_url
from backend.app.utils.http_client import request_with_retry


class AccountPresenceState(str, Enum):

    CONFIRMED = "confirmed"
    NOT_FOUND = "not_found"
    UNKNOWN = "unknown"
    BLOCKED = "blocked"
    RATE_LIMITED = "rate_limited"
    FAILED = "failed"


_CONFIDENCE_BY_STATE = {
    AccountPresenceState.CONFIRMED: "high",
    AccountPresenceState.NOT_FOUND: "high",
    AccountPresenceState.UNKNOWN: "low",
    AccountPresenceState.BLOCKED: "low",
    AccountPresenceState.RATE_LIMITED: "low",
    AccountPresenceState.FAILED: "none",
}


@dataclass
class PlatformPresenceResult:

    platform: str
    domain: str
    category: str
    status: AccountPresenceState
    confidence: str
    evidence: str
    http_status: int | None
    checked_at: str
    provider_reason: str | None = None
    # Only set when the platform's own response legitimately
    # establishes a specific profile URL for this address (most
    # sign-up/availability checks, including GitHub's and
    # SoundCloud's below, only confirm existence and never hand back
    # a username/profile path — so this stays None for them rather
    # than guessing one).
    profile_url: str | None = None
    latency_ms: int = 0


CheckerFn = Callable[[httpx.AsyncClient, str], Awaitable[PlatformPresenceResult]]


@dataclass
class PresencePlatform:

    name: str
    domain: str
    category: str
    checker: CheckerFn


def _result(
    platform: "PresencePlatform",
    state: AccountPresenceState,
    evidence: str,
    *,
    http_status: int | None,
    start: float,
    provider_reason: str | None = None,
    profile_url: str | None = None,
) -> PlatformPresenceResult:

    return PlatformPresenceResult(
        platform=platform.name,
        domain=platform.domain,
        category=platform.category,
        status=state,
        confidence=_CONFIDENCE_BY_STATE[state],
        evidence=evidence,
        http_status=http_status,
        checked_at=datetime.now(timezone.utc).isoformat(),
        provider_reason=provider_reason,
        profile_url=profile_url,
        latency_ms=round((time.perf_counter() - start) * 1000),
    )


# ------------------------------------------------------
# Live, working checks
# ------------------------------------------------------
#
# Each function performs ONE well-scoped, low-ambiguity check against
# a publicly documented, unauthenticated endpoint. We deliberately do
# not attempt to replicate holehe's full ~150-site catalogue: many of
# those checks rely on scraping login-form HTML that changes without
# notice, or on platforms that actively anti-bot-wall this exact
# technique (see BLOCKED_BY_DESIGN_PLATFORMS below for those). Starting
# with a small, well-understood set keeps false CONFIRMED/NOT_FOUND
# results rare; more platforms can be added the same way once each one
# is validated against the live site.

async def _check_github(client: httpx.AsyncClient, email: str) -> PlatformPresenceResult:
    """
    GitHub's public sign-up form validates the email address against
    existing accounts client-side, via POST /signup_check/email:
    HTTP 422 = address already registered, HTTP 200 = available.
    """

    platform = _GITHUB
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
            return _result(
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
            return _result(
                platform, AccountPresenceState.CONFIRMED,
                "GitHub's signup_check/email endpoint returned HTTP 422 "
                "(address already registered).",
                http_status=response.status_code, start=start,
            )

        if response.status_code == 200:
            return _result(
                platform, AccountPresenceState.NOT_FOUND,
                "GitHub's signup_check/email endpoint returned HTTP 200 "
                "(address available).",
                http_status=response.status_code, start=start,
            )

        if response.status_code == 429:
            return _result(
                platform, AccountPresenceState.RATE_LIMITED,
                "GitHub rate-limited the signup check.",
                http_status=response.status_code, start=start,
                provider_reason="HTTP 429 from signup_check/email.",
            )

        return _result(
            platform, AccountPresenceState.UNKNOWN,
            f"Unexpected HTTP {response.status_code} from signup_check/email.",
            http_status=response.status_code, start=start,
        )

    except (IntegrationTimeoutError, httpx.ConnectError, httpx.RemoteProtocolError) as error:
        return _result(
            platform, AccountPresenceState.FAILED,
            f"Network error before a response was received: {error.__class__.__name__}.",
            http_status=None, start=start,
            provider_reason=f"Network error: {error.__class__.__name__}",
        )

    except ValueError as error:
        return _result(
            platform, AccountPresenceState.FAILED,
            str(error), http_status=None, start=start, provider_reason=str(error),
        )


async def _check_soundcloud(client: httpx.AsyncClient, email: str) -> PlatformPresenceResult:
    """
    SoundCloud's identifier-availability endpoint reports whether an
    email is already in use during sign-up:
    GET /web-auth/identifier?q=<email> -> {"status": "in_use" | "available" | ...}.
    """

    platform = _SOUNDCLOUD
    start = time.perf_counter()
    url = f"https://api-auth.soundcloud.com/web-auth/identifier?q={email}"

    try:
        assert_public_url(url)

        response = await request_with_retry(client, "GET", url, max_retries=0)

        if response.status_code == 429:
            return _result(
                platform, AccountPresenceState.RATE_LIMITED,
                "SoundCloud rate-limited the identifier check.",
                http_status=response.status_code, start=start,
                provider_reason="HTTP 429 from web-auth/identifier.",
            )

        if response.status_code != 200:
            return _result(
                platform, AccountPresenceState.UNKNOWN,
                f"Unexpected HTTP {response.status_code} from web-auth/identifier.",
                http_status=response.status_code, start=start,
            )

        try:
            payload = response.json()
        except ValueError:
            return _result(
                platform, AccountPresenceState.UNKNOWN,
                "Response body was not valid JSON.",
                http_status=response.status_code, start=start,
            )

        api_status = payload.get("status")

        if api_status == "in_use":
            return _result(
                platform, AccountPresenceState.CONFIRMED,
                "SoundCloud's identifier endpoint returned status=\"in_use\".",
                http_status=response.status_code, start=start,
            )

        if api_status == "available":
            return _result(
                platform, AccountPresenceState.NOT_FOUND,
                "SoundCloud's identifier endpoint returned status=\"available\".",
                http_status=response.status_code, start=start,
            )

        return _result(
            platform, AccountPresenceState.UNKNOWN,
            f"Unrecognized status value from identifier endpoint: {api_status!r}.",
            http_status=response.status_code, start=start,
        )

    except (IntegrationTimeoutError, httpx.ConnectError, httpx.RemoteProtocolError) as error:
        return _result(
            platform, AccountPresenceState.FAILED,
            f"Network error before a response was received: {error.__class__.__name__}.",
            http_status=None, start=start,
            provider_reason=f"Network error: {error.__class__.__name__}",
        )

    except ValueError as error:
        return _result(
            platform, AccountPresenceState.FAILED,
            str(error), http_status=None, start=start, provider_reason=str(error),
        )


_GITHUB = PresencePlatform(
    name="github", domain="github.com", category="developer", checker=_check_github,
)

_SOUNDCLOUD = PresencePlatform(
    name="soundcloud", domain="soundcloud.com", category="entertainment", checker=_check_soundcloud,
)


# ------------------------------------------------------
# BLOCKED-by-design platforms
# ------------------------------------------------------
#
# These are platforms explicitly requested for coverage where, on
# inspection, no reliable *unauthenticated* signal exists today without
# doing something this project's privacy/security rules forbid outright
# (defeating a CAPTCHA/anti-bot wall, replaying an authenticated
# session, or completing an actual account-recovery flow against a real
# account). Rather than silently omitting them or building something
# fragile on top of scraped, frequently-changed HTML that would produce
# unreliable CONFIRMED/NOT_FOUND results, each reports BLOCKED with an
# honest reason and makes no network request at all. This list should
# only grow via the same path GitHub/SoundCloud took: a specific,
# verified, unauthenticated endpoint - not by removing entries from
# here without one.

_BLOCKED_BY_DESIGN: list[tuple[str, str, str]] = [
    # (platform name, domain, honest reason)
    (
        "instagram", "instagram.com",
        "Instagram's password-reset/signup flows sit behind anti-bot "
        "challenges (rate limiting and CAPTCHA) specifically to prevent "
        "this kind of automated account-existence check; no reliable "
        "unauthenticated signal is available without attempting to "
        "defeat those controls, which this platform does not do.",
    ),
    (
        "linkedin", "linkedin.com",
        "LinkedIn requires authentication for account-existence-adjacent "
        "endpoints and its terms explicitly prohibit unauthenticated "
        "automated querying; no legitimate unauthenticated signal is "
        "available.",
    ),
]


def _make_blocked_platform(name: str, domain: str, reason: str) -> PresencePlatform:

    async def _checker(client: httpx.AsyncClient, email: str) -> PlatformPresenceResult:
        start = time.perf_counter()
        return _result(
            platform, AccountPresenceState.BLOCKED,
            "No unauthenticated check was attempted for this platform.",
            http_status=None, start=start, provider_reason=reason,
        )

    platform = PresencePlatform(name=name, domain=domain, category="social", checker=_checker)
    return platform


def default_presence_platforms() -> list[PresencePlatform]:
    return [
        _GITHUB,
        _SOUNDCLOUD,
        *(_make_blocked_platform(name, domain, reason) for name, domain, reason in _BLOCKED_BY_DESIGN),
    ]


async def run_presence_checks(
    email: str,
    platforms: list[PresencePlatform] | None = None,
) -> list[PlatformPresenceResult]:
    """
    Fans an email address out across the configured platforms
    concurrently, bounded by the same concurrency ceiling the username
    module uses (EMAIL_ACCOUNT_PRESENCE_MAX_CONCURRENCY).
    """

    targets = platforms if platforms is not None else default_presence_platforms()
    semaphore = asyncio.Semaphore(settings.EMAIL_ACCOUNT_PRESENCE_MAX_CONCURRENCY)

    async with httpx.AsyncClient(
        timeout=settings.EMAIL_ACCOUNT_PRESENCE_TIMEOUT_SECONDS,
    ) as client:

        async def _bounded(platform: PresencePlatform) -> PlatformPresenceResult:
            async with semaphore:
                return await platform.checker(client, email)

        return list(await asyncio.gather(*(_bounded(p) for p in targets)))
