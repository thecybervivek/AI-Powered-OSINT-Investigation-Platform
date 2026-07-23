import asyncio
import ipaddress
import logging
import socket
from urllib.parse import urlparse

import httpx

from backend.app.core.config import settings
from backend.app.integrations.exceptions import IntegrationTimeoutError

logger = logging.getLogger("app.utils.http_client")


# ==========================================================
# SSRF Guard
# ==========================================================

_BLOCKED_HOSTNAMES = {
    "localhost",
    "metadata.google.internal",
}


def assert_public_url(url: str) -> None:
    """
    Defends every outbound OSINT call against SSRF: rejects targets that
    resolve to loopback, link-local, private, or multicast address space,
    and rejects the cloud metadata hostname outright. Raises ValueError
    on anything unsafe; callers should treat that as a failed lookup
    rather than let the request through.
    """

    parsed = urlparse(url)

    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"Unsupported URL scheme: {parsed.scheme}")

    hostname = parsed.hostname

    if not hostname:
        raise ValueError("URL has no hostname.")

    if hostname.lower() in _BLOCKED_HOSTNAMES:
        raise ValueError(f"Blocked hostname: {hostname}")

    try:
        # If the hostname is already a literal IP this succeeds directly;
        # otherwise resolve it so we validate the address actually used.
        try:
            addr = ipaddress.ip_address(hostname)
            candidates = [addr]

        except ValueError:
            infos = socket.getaddrinfo(hostname, None)
            candidates = [ipaddress.ip_address(info[4][0]) for info in infos]

    except socket.gaierror as error:
        raise ValueError(f"Could not resolve hostname: {hostname}") from error

    for addr in candidates:

        if (
            addr.is_loopback
            or addr.is_link_local
            or addr.is_multicast
            or addr.is_reserved
            or addr.is_unspecified
            or (addr.is_private and not _allow_private_target())
        ):
            raise ValueError(
                f"URL resolves to a non-public address ({addr}); refusing to fetch."
            )


def _allow_private_target() -> bool:
    """
    Investigation targets are sometimes internal-network IPs/domains the
    analyst legitimately owns (e.g. auditing their own infrastructure).
    Kept as a single override point rather than silently allowing private
    ranges everywhere. Defaults to disallow.
    """

    return False


# ==========================================================
# Retrying Async Request
# ==========================================================

async def request_with_retry(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    *,
    max_retries: int | None = None,
    backoff_seconds: float | None = None,
    **kwargs,
) -> httpx.Response:
    """
    Issues a single outbound request with bounded retries on transient
    network failures (timeouts, connection resets). Does NOT retry on
    4xx/5xx HTTP responses — those are returned as-is for the caller to
    interpret (a 404 is meaningful data for OSINT checks, not a failure).
    """

    retries = settings.OSINT_MAX_RETRIES if max_retries is None else max_retries
    backoff = (
        settings.OSINT_RETRY_BACKOFF_SECONDS
        if backoff_seconds is None
        else backoff_seconds
    )

    headers = kwargs.pop("headers", {}) or {}
    headers.setdefault("User-Agent", settings.OSINT_HTTP_USER_AGENT)

    last_error: Exception | None = None

    for attempt in range(retries + 1):

        try:
            return await client.request(
                method,
                url,
                headers=headers,
                **kwargs,
            )

        except (httpx.ConnectTimeout, httpx.ReadTimeout, httpx.WriteTimeout):
            last_error = IntegrationTimeoutError(
                f"Request to {url} timed out after {attempt + 1} attempt(s)."
            )

        except (httpx.ConnectError, httpx.RemoteProtocolError) as error:
            last_error = error

        if attempt < retries:
            await asyncio.sleep(backoff * (attempt + 1))

    if isinstance(last_error, IntegrationTimeoutError):
        raise last_error

    raise IntegrationTimeoutError(
        f"Request to {url} failed after {retries + 1} attempt(s): {last_error}"
    )
