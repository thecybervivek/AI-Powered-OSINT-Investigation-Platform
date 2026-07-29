import asyncio
import logging
import re
import time
from dataclasses import dataclass

import httpx

from backend.app.core.config import settings
from backend.app.integrations.exceptions import IntegrationTimeoutError
from backend.app.integrations.username.platforms import DetectionMethod
from backend.app.integrations.username.platforms import PlatformDefinition
from backend.app.utils.http_client import assert_public_url
from backend.app.utils.http_client import request_with_retry

logger = logging.getLogger("app.integrations.username")

_USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9_.\-]{1,64}$")


@dataclass
class PlatformCheckResult:

    platform: str
    category: str
    exists: bool | None  # None = inconclusive (network error, blocked, etc.)
    profile_url: str
    http_status: int | None
    latency_ms: int
    error: str | None = None


def is_valid_username(username: str) -> bool:
    """
    Conservative allow-list validation: OSINT username targets are
    reflected directly into outbound URLs, so we reject anything that
    isn't a plausible handle before it ever reaches httpx.
    """

    return bool(_USERNAME_PATTERN.match(username))


async def check_single_platform(
    client: httpx.AsyncClient,
    semaphore: asyncio.Semaphore,
    platform: PlatformDefinition,
    username: str,
) -> PlatformCheckResult:

    profile_url = platform.url_template.format(username)
    start = time.perf_counter()

    async with semaphore:

        try:
            assert_public_url(profile_url)

            # request_with_retry re-validates every redirect hop and
            # pins each connection to its validated IP (see
            # utils/http_client.py) - a platform's own redirect can't
            # be used to reach an internal target. max_retries=0
            # preserves this call site's existing fail-fast-per-platform
            # behavior: with 30-100+ platforms checked per investigation,
            # retrying a single slow/down site would slow the whole
            # batch for no benefit - a platform that fails once is
            # simply reported inconclusive, same as before.
            response = await request_with_retry(
                client,
                "GET",
                profile_url,
                max_retries=0,
                headers={"User-Agent": settings.OSINT_HTTP_USER_AGENT},
                timeout=settings.USERNAME_CHECK_TIMEOUT_SECONDS,
            )

            latency_ms = round((time.perf_counter() - start) * 1000)

            exists = _evaluate_existence(platform, response)

            return PlatformCheckResult(
                platform=platform.name,
                category=platform.category,
                exists=exists,
                profile_url=profile_url,
                http_status=response.status_code,
                latency_ms=latency_ms,
            )

        except (IntegrationTimeoutError, httpx.ConnectError, httpx.RemoteProtocolError) as error:

            return PlatformCheckResult(
                platform=platform.name,
                category=platform.category,
                exists=None,
                profile_url=profile_url,
                http_status=None,
                latency_ms=round((time.perf_counter() - start) * 1000),
                error=f"Network error: {error.__class__.__name__}",
            )

        except ValueError as error:

            return PlatformCheckResult(
                platform=platform.name,
                category=platform.category,
                exists=None,
                profile_url=profile_url,
                http_status=None,
                latency_ms=round((time.perf_counter() - start) * 1000),
                error=str(error),
            )

        except Exception as error:  # pragma: no cover - defensive catch-all

            logger.warning(
                "Unexpected error checking platform.",
                extra={"event": "username_platform_check_error", "platform": platform.name},
            )

            return PlatformCheckResult(
                platform=platform.name,
                category=platform.category,
                exists=None,
                profile_url=profile_url,
                http_status=None,
                latency_ms=round((time.perf_counter() - start) * 1000),
                error=str(error),
            )


def _evaluate_existence(
    platform: PlatformDefinition,
    response: httpx.Response,
) -> bool | None:

    if platform.detection_method == DetectionMethod.STATUS_CODE:
        return response.status_code == platform.existing_status

    if platform.detection_method == DetectionMethod.ERROR_STRING_IN_BODY:

        if response.status_code >= 500:
            return None

        body = response.text[:200_000]  # cap to avoid scanning huge pages
        marker = platform.missing_marker or ""

        return marker.lower() not in body.lower()

    if platform.detection_method == DetectionMethod.REDIRECT_ON_MISSING:
        return not (300 <= response.status_code < 400)

    return None


async def run_platform_checks(
    username: str,
    platforms: list[PlatformDefinition],
) -> list[PlatformCheckResult]:
    """
    Fans a username out across every platform in `platforms` concurrently,
    bounded by USERNAME_MAX_CONCURRENCY so we never open unbounded parallel
    connections to third-party sites.
    """

    semaphore = asyncio.Semaphore(settings.USERNAME_MAX_CONCURRENCY)

    async with httpx.AsyncClient(
        timeout=settings.USERNAME_CHECK_TIMEOUT_SECONDS,
    ) as client:

        tasks = [
            check_single_platform(client, semaphore, platform, username)
            for platform in platforms
        ]

        return list(await asyncio.gather(*tasks))
