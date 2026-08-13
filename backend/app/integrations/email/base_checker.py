"""
Email → account & social presence checking ("does this address have an
account on platform X?"), architecturally mirroring the username
module's base_checker.py: a shared tri-... six-state result model, a
platform registry, and a bounded-concurrency fan-out helper. Each
individual platform check lives in its own file under checkers/ (see
checkers/__init__.py for the registry) rather than one large file, so
each is independently testable and independently extensible.

States:

    CONFIRMED     - reliable evidence the address is registered
    NOT_FOUND     - provider gave a reliable negative result
    UNKNOWN       - provider didn't give enough evidence either way
                    (unexpected response shape, upstream page changed)
    BLOCKED       - provider's anti-automation controls would have to
                    be defeated to get a real answer, or the platform
                    doesn't expose an email-existence signal at all -
                    this project does not defeat CAPTCHAs/anti-bot
                    controls, so these platforms report BLOCKED with
                    an honest reason instead of a fabricated result
    RATE_LIMITED  - provider explicitly rate-limited the request
    FAILED        - the request itself didn't complete (network/timeout)

Hard rule enforced throughout every checker: 401/403/429/CAPTCHA/anti-
bot/network-error responses are NEVER mapped to NOT_FOUND. A CONFIRMED
or NOT_FOUND result is only ever produced from a response that
positively, unambiguously establishes that state - never inferred from
a merely "positive-looking" status code in isolation, and never a
constructed URL/guess.

Only unauthenticated, publicly-reachable endpoints are used. Nothing in
this package replays session cookies, defeats a CAPTCHA/WAF challenge,
or completes an actual registration/password-reset. See each
checkers/<platform>.py module for that platform's specific, honest
justification when it reports BLOCKED.
"""

import asyncio
import time
from dataclasses import dataclass
from datetime import datetime
from datetime import timezone
from enum import Enum
from typing import Awaitable
from typing import Callable

import httpx

from backend.app.core.config import settings


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
class PlatformCheckResult:

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
    # establishes a specific profile URL for this address. Most
    # sign-up/availability checks only confirm existence and never
    # hand back a profile path, so this stays None for them rather
    # than guessing one - never fabricate a profile URL.
    profile_url: str | None = None
    latency_ms: int = 0

    def to_dict(self) -> dict:
        return {
            "platform": self.platform,
            "domain": self.domain,
            "category": self.category,
            "status": self.status.value,
            "confidence": self.confidence,
            "evidence": self.evidence,
            "http_status": self.http_status,
            "checked_at": self.checked_at,
            "provider_reason": self.provider_reason,
            "profile_url": self.profile_url,
            "latency_ms": self.latency_ms,
        }


CheckerFn = Callable[[httpx.AsyncClient, str], Awaitable[PlatformCheckResult]]


@dataclass
class PresencePlatform:

    name: str
    domain: str
    category: str
    checker: CheckerFn


def make_result(
    platform: "PresencePlatform",
    state: AccountPresenceState,
    evidence: str,
    *,
    http_status: int | None,
    start: float,
    provider_reason: str | None = None,
    profile_url: str | None = None,
) -> PlatformCheckResult:

    return PlatformCheckResult(
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


def make_blocked_platform(name: str, domain: str, category: str, reason: str) -> PresencePlatform:
    """
    Builds a stub PresencePlatform that makes NO network request at
    all and always reports BLOCKED with the given honest reason. Used
    by every checkers/<platform>.py module for a platform where no
    reliable, legitimate, unauthenticated email-existence signal is
    available today - see each module's docstring for the specific
    justification (anti-bot controls, no such signal exists, or the
    platform isn't email-account-based at all).
    """

    async def _checker(client: httpx.AsyncClient, email: str) -> PlatformCheckResult:
        start = time.perf_counter()
        return make_result(
            platform, AccountPresenceState.BLOCKED,
            "No unauthenticated check was attempted for this platform.",
            http_status=None, start=start, provider_reason=reason,
        )

    platform = PresencePlatform(name=name, domain=domain, category=category, checker=_checker)
    return platform


async def run_presence_checks(
    email: str,
    platforms: list[PresencePlatform],
) -> list[PlatformCheckResult]:
    """
    Fans an email address out across the configured platforms
    concurrently, bounded by EMAIL_ACCOUNT_PRESENCE_MAX_CONCURRENCY.
    """

    semaphore = asyncio.Semaphore(settings.EMAIL_ACCOUNT_PRESENCE_MAX_CONCURRENCY)

    async with httpx.AsyncClient(
        timeout=settings.EMAIL_ACCOUNT_PRESENCE_TIMEOUT_SECONDS,
    ) as client:

        async def _bounded(platform: PresencePlatform) -> PlatformCheckResult:
            async with semaphore:
                return await platform.checker(client, email)

        return list(await asyncio.gather(*(_bounded(p) for p in platforms)))
