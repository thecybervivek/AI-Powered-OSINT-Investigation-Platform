from urllib.parse import urljoin
from urllib.parse import urlparse

import httpx

from backend.app.core.config import settings
from backend.app.integrations.base import AsyncBaseIntegration
from backend.app.integrations.base import IntegrationResult
from backend.app.models.investigation import ModuleResultStatus
from backend.app.utils.http_client import assert_public_url

_MAX_REDIRECTS = 10
_BODY_SAMPLE_BYTES = 200_000

# Read-with-safe-default headers, so a missing header reports as
# genuinely absent (None) rather than being confused with "not
# checked" - the UI needs to tell these apart.
_SECURITY_HEADER_NAMES = (
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
)


class HttpResponseIntegration(AsyncBaseIntegration):
    """
    Direct, SSRF-safe fetch of the target URL, following redirects
    manually so the full chain can be reported.

    Deliberately does NOT reuse http_client.request_with_retry's own
    redirect loop: that function intentionally returns only the final
    response (by design, for every other caller's needs) and discards
    the intermediate hops. This integration exists specifically to
    surface "Redirect Analysis" (original -> intermediate -> final),
    so it re-implements the same hop-by-hop loop locally - reusing
    `assert_public_url` (imported, not modified) for identical SSRF
    validation at every single hop, exactly mirroring
    request_with_retry's own safety guarantee rather than weakening it.

    No credentials required - this is a direct HTTP request to the
    target itself, not a third-party API.
    """

    source_name = "http_response"

    def is_configured(self) -> bool:
        return True

    async def _query(self, target: str) -> IntegrationResult:

        chain: list[dict] = []
        current_url = target
        response: httpx.Response | None = None

        headers = {"User-Agent": settings.OSINT_HTTP_USER_AGENT}

        async with httpx.AsyncClient(timeout=settings.OSINT_REQUEST_TIMEOUT_SECONDS) as client:

            for _ in range(_MAX_REDIRECTS + 1):

                assert_public_url(current_url)

                response = await client.get(
                    current_url,
                    headers=headers,
                    follow_redirects=False,
                )

                chain.append(
                    {"url": current_url, "status_code": response.status_code}
                )

                if response.status_code not in (301, 302, 303, 307, 308):
                    break

                location = response.headers.get("location")

                if not location:
                    break

                current_url = urljoin(str(response.url), location)

            else:

                return IntegrationResult(
                    source=self.source_name,
                    status=ModuleResultStatus.FAILED,
                    error_message="Too many redirects.",
                )

        assert response is not None  # loop always assigns before break/return

        final_url = current_url
        parsed_final = urlparse(final_url)
        response_headers = {k.lower(): v for k, v in response.headers.items()}

        security_headers = {
            name: response_headers.get(name) for name in _SECURITY_HEADER_NAMES
        }

        page_title = _extract_title(response.text[:_BODY_SAMPLE_BYTES])
        favicon = _extract_favicon(response.text[:_BODY_SAMPLE_BYTES], final_url)

        data = {
            "original_url": target,
            "final_url": final_url,
            "redirect_count": len(chain) - 1,
            "redirect_chain": chain,
            "http_status": response.status_code,
            "https_enforced": parsed_final.scheme == "https",
            "canonical_host": parsed_final.hostname,
            "content_type": response_headers.get("content-type"),
            "server": response_headers.get("server"),
            "page_title": page_title,
            "favicon": favicon,
            "security_headers": security_headers,
            "response_headers": response_headers,
        }

        return IntegrationResult(
            source=self.source_name,
            status=ModuleResultStatus.SUCCESS,
            data=data,
        )


def _extract_title(body_sample: str) -> str | None:

    lower = body_sample.lower()
    start = lower.find("<title")

    if start == -1:
        return None

    start = lower.find(">", start)

    if start == -1:
        return None

    end = lower.find("</title>", start)

    if end == -1:
        return None

    title = body_sample[start + 1 : end].strip()

    return title or None


def _extract_favicon(body_sample: str, final_url: str) -> str | None:
    """
    Looks for an explicit <link rel="icon" ...> (or "shortcut icon")
    tag and resolves its href against the final URL. Returns None
    when no such tag is found - deliberately does NOT fall back to
    guessing the conventional /favicon.ico path, since that would be
    presenting an unconfirmed guess as if it were observed evidence.
    """

    lower = body_sample.lower()

    for rel_marker in ('rel="icon"', "rel='icon'", 'rel="shortcut icon"', "rel='shortcut icon'"):

        idx = lower.find(rel_marker)

        if idx == -1:
            continue

        tag_start = lower.rfind("<link", 0, idx)

        if tag_start == -1:
            continue

        tag_end = lower.find(">", idx)

        if tag_end == -1:
            continue

        tag = body_sample[tag_start:tag_end]
        href_idx = tag.lower().find("href=")

        if href_idx == -1:
            continue

        quote_char = tag[href_idx + 5 : href_idx + 6]

        if quote_char not in ("'", '"'):
            continue

        href_start = href_idx + 6
        href_end = tag.find(quote_char, href_start)

        if href_end == -1:
            continue

        href = tag[href_start:href_end].strip()

        if href:
            return urljoin(final_url, href)

    return None
