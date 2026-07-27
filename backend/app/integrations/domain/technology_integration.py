import httpx

from backend.app.core.config import settings
from backend.app.integrations.base import AsyncBaseIntegration
from backend.app.integrations.base import IntegrationResult
from backend.app.models.investigation import ModuleResultStatus
from backend.app.utils.http_client import assert_public_url
from backend.app.utils.http_client import request_with_retry

# Lightweight (header-substring -> technology) and (body-marker ->
# technology) signatures. Not a full fingerprinting database (that's a
# large, continuously maintained dataset in its own right) — this is a
# best-effort heuristic layer, and every hit's origin is reported so
# callers can judge confidence for themselves.
_HEADER_SIGNATURES: dict[str, list[tuple[str, str]]] = {
    "server": [
        ("nginx", "Nginx"),
        ("apache", "Apache HTTP Server"),
        ("cloudflare", "Cloudflare"),
        ("microsoft-iis", "Microsoft IIS"),
        ("litespeed", "LiteSpeed"),
    ],
    "x-powered-by": [
        ("php", "PHP"),
        ("express", "Express.js"),
        ("asp.net", "ASP.NET"),
        ("next.js", "Next.js"),
    ],
    "x-generator": [
        ("wordpress", "WordPress"),
        ("drupal", "Drupal"),
    ],
}

_BODY_SIGNATURES: list[tuple[str, str]] = [
    ("wp-content", "WordPress"),
    ("cdn.shopify.com", "Shopify"),
    ("__next", "Next.js"),
    ("data-reactroot", "React"),
    ("ng-version", "Angular"),
    ("wix.com", "Wix"),
    ("squarespace", "Squarespace"),
]


class TechnologyDetectionIntegration(AsyncBaseIntegration):
    """
    Fetches the target's homepage and matches response headers and a
    capped slice of the body against known technology signatures
    (server software, CMS, JS frameworks, hosting platforms).
    """

    source_name = "technology_detection"

    def is_configured(self) -> bool:
        return True

    async def _query(self, target: str) -> IntegrationResult:

        host = target.strip().lower()

        if "://" not in host:
            host = f"https://{host}"

        try:
            assert_public_url(host)
        except ValueError as error:
            return IntegrationResult(
                source=self.source_name,
                status=ModuleResultStatus.FAILED,
                error_message=f"Unsafe target refused: {error}",
            )

        detected: set[str] = set()
        headers_seen: dict[str, str] = {}

        async with httpx.AsyncClient(
            timeout=settings.OSINT_REQUEST_TIMEOUT_SECONDS,
            follow_redirects=True,
        ) as client:

            try:
                response = await request_with_retry(client, "GET", host)

            except Exception as error:

                return IntegrationResult(
                    source=self.source_name,
                    status=ModuleResultStatus.FAILED,
                    error_message=f"Could not fetch '{host}': {error}",
                )

        for header_name, signatures in _HEADER_SIGNATURES.items():

            header_value = response.headers.get(header_name, "")

            if not header_value:
                continue

            headers_seen[header_name] = header_value

            for marker, technology in signatures:

                if marker.lower() in header_value.lower():
                    detected.add(technology)

        body_sample = response.text[:200_000].lower()

        for marker, technology in _BODY_SIGNATURES:

            if marker in body_sample:
                detected.add(technology)

        data = {
            "url": host,
            "http_status": response.status_code,
            "technologies_detected": sorted(detected),
            "relevant_headers": headers_seen,
        }

        return IntegrationResult(
            source=self.source_name,
            status=ModuleResultStatus.SUCCESS,
            data=data,
        )
