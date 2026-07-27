import asyncio
import ipaddress
import logging
import socket
from urllib.parse import urljoin, urlparse

import httpx

from backend.app.core.config import settings
from backend.app.integrations.exceptions import IntegrationTimeoutError

logger = logging.getLogger("app.utils.http_client")

_BLOCKED_HOSTNAMES = {
    "localhost",
    "localhost.localdomain",
    "metadata.google.internal",
}

_MAX_REDIRECTS = 5


def resolve_public_addresses(
    hostname: str,
) -> tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, ...]:
    host = hostname.rstrip(".").lower()

    if host in _BLOCKED_HOSTNAMES or host.endswith(".localhost"):
        raise ValueError("Blocked destination hostname.")

    try:
        try:
            candidates = [ipaddress.ip_address(host)]

        except ValueError:
            infos = socket.getaddrinfo(
                host,
                None,
                type=socket.SOCK_STREAM,
            )

            candidates = list(
                {
                    ipaddress.ip_address(info[4][0])
                    for info in infos
                }
            )

    except socket.gaierror as error:
        raise ValueError(
            "Destination hostname could not be resolved."
        ) from error

    if not candidates:
        raise ValueError(
            "Destination hostname resolved to no addresses."
        )

    for addr in candidates:
        if (
            not addr.is_global
            or addr.is_private
            or addr.is_loopback
            or addr.is_link_local
            or addr.is_multicast
            or addr.is_reserved
            or addr.is_unspecified
        ):
            raise ValueError(
                "Destination resolves to a non-public address."
            )

    return tuple(candidates)


def assert_public_url(url: str) -> None:
    parsed = urlparse(url)

    if parsed.scheme not in {"http", "https"}:
        raise ValueError(
            "Only HTTP(S) destinations are permitted."
        )

    if parsed.username or parsed.password:
        raise ValueError(
            "User-info in outbound URLs is not permitted."
        )

    if not parsed.hostname:
        raise ValueError(
            "URL has no hostname."
        )

    resolve_public_addresses(parsed.hostname)


async def request_with_retry(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    *,
    max_retries: int | None = None,
    backoff_seconds: float | None = None,
    enforce_public_destination: bool = True,
    **kwargs,
) -> httpx.Response:
    """
    Central outbound HTTP policy.

    Every outbound destination and redirect hop is validated before
    the request is sent.

    DNS is checked immediately before each request. httpx still performs
    its own DNS resolution, so application-layer validation cannot fully
    eliminate DNS rebinding. Production egress filtering/firewall rules
    must independently block private, loopback, link-local, multicast,
    reserved, unspecified, and metadata networks.
    """

    retries = (
        settings.OSINT_MAX_RETRIES
        if max_retries is None
        else max_retries
    )

    backoff = (
        settings.OSINT_RETRY_BACKOFF_SECONDS
        if backoff_seconds is None
        else backoff_seconds
    )

    headers = kwargs.pop("headers", {}) or {}
    headers.setdefault(
        "User-Agent",
        settings.OSINT_HTTP_USER_AGENT,
    )

    # Redirects are handled manually so every destination can be
    # validated before following it.
    kwargs.pop("follow_redirects", None)

    last_error: Exception | None = None

    for attempt in range(retries + 1):
        current_url = url
        current_method = method

        try:
            for _ in range(_MAX_REDIRECTS + 1):

                if enforce_public_destination:
                    assert_public_url(current_url)

                response = await client.request(
                    current_method,
                    current_url,
                    headers=headers,
                    follow_redirects=False,
                    **kwargs,
                )

                if response.status_code not in {
                    301,
                    302,
                    303,
                    307,
                    308,
                }:
                    return response

                location = response.headers.get("location")

                if not location:
                    return response

                current_url = urljoin(
                    str(response.url),
                    location,
                )

                # RFC semantics:
                # 303 redirects become GET.
                # Common 301/302 POST redirects also become GET.
                if (
                    response.status_code == 303
                    or (
                        response.status_code in {301, 302}
                        and current_method.upper() == "POST"
                    )
                ):
                    current_method = "GET"

                    kwargs.pop("json", None)
                    kwargs.pop("data", None)
                    kwargs.pop("content", None)

            raise httpx.TooManyRedirects(
                "Too many redirects"
            )

        except ValueError:
            # Security-policy violations must not be retried.
            raise

        except (
            httpx.ConnectTimeout,
            httpx.ReadTimeout,
            httpx.WriteTimeout,
        ):
            last_error = IntegrationTimeoutError(
                "Outbound request timed out after "
                f"{attempt + 1} attempt(s)."
            )

        except (
            httpx.ConnectError,
            httpx.RemoteProtocolError,
            httpx.TooManyRedirects,
        ) as error:
            last_error = error

        if attempt < retries:
            await asyncio.sleep(
                backoff * (attempt + 1)
            )

    if isinstance(
        last_error,
        IntegrationTimeoutError,
    ):
        raise last_error

    raise IntegrationTimeoutError(
        "Outbound request failed after "
        f"{retries + 1} attempt(s)."
    )