import asyncio
import re
from datetime import datetime
from datetime import timezone

from backend.app.core.config import settings
from backend.app.integrations.base import AsyncBaseIntegration
from backend.app.integrations.base import IntegrationResult
from backend.app.integrations.exceptions import IntegrationTimeoutError
from backend.app.models.investigation import ModuleResultStatus

# WHOIS registries format dates inconsistently; these cover the vast
# majority seen in practice (ISO-8601 with/without a 'Z', and the
# older free-text "05-jan-2020" style some ccTLD registries still use).
# Never raises - callers get None back for anything that doesn't match
# rather than the whole lookup failing over a date-format quirk.
_WHOIS_DATE_FORMATS = (
    "%Y-%m-%dT%H:%M:%SZ",
    "%Y-%m-%dT%H:%M:%S.%fZ",
    "%Y-%m-%dT%H:%M:%S%z",
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%d",
    "%d-%b-%Y",
    "%d-%m-%Y",
)


def _parse_whois_date(raw: str | None) -> datetime | None:

    if not raw:
        return None

    cleaned = raw.strip()

    for fmt in _WHOIS_DATE_FORMATS:

        try:
            parsed = datetime.strptime(cleaned, fmt)

            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)

            return parsed

        except ValueError:
            continue

    return None


def _domain_age_days(creation_date_raw: str | None) -> int | None:

    parsed = _parse_whois_date(creation_date_raw)

    if parsed is None:
        return None

    age = (datetime.now(timezone.utc) - parsed).days

    # A "future" creation date means either a parsing mismatch or a
    # clock-skewed WHOIS server - either way, an age isn't meaningful.
    return age if age >= 0 else None

_WHOIS_PORT = 43
_IANA_WHOIS_HOST = "whois.iana.org"

_REFERRAL_PATTERN = re.compile(r"(?im)^\s*(?:whois|refer)\s*:\s*(\S+)")

_FIELD_PATTERNS = {
    "registrar": re.compile(r"(?im)^\s*Registrar:\s*(.+)$"),
    "creation_date": re.compile(r"(?im)^\s*(?:Creation Date|Registered on|created):\s*(.+)$"),
    "expiration_date": re.compile(r"(?im)^\s*(?:Registry Expiry Date|Expiry date|paid-till):\s*(.+)$"),
    "updated_date": re.compile(r"(?im)^\s*(?:Updated Date|last-updated|changed):\s*(.+)$"),
    "domain_status": re.compile(r"(?im)^\s*Domain Status:\s*(.+)$"),
}

# A real WHOIS/RDAP record commonly lists several Domain Status values
# (e.g. clientTransferProhibited AND clientUpdateProhibited on the same
# domain). The original `domain_status` field above only ever captured
# the first match - kept as-is for backward compatibility with any
# existing caller - this additional pattern collects all of them into
# a new `domain_statuses` list field instead of replacing it.
_ALL_DOMAIN_STATUS_PATTERN = re.compile(r"(?im)^\s*Domain Status:\s*(\S+)")

_DNSSEC_PATTERN = re.compile(r"(?im)^\s*DNSSEC:\s*(.+)$")

_NAME_SERVER_PATTERN = re.compile(r"(?im)^\s*Name Server:\s*(\S+)$")


async def _whois_query(host: str, query: str, timeout: float) -> str:

    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(host, _WHOIS_PORT),
        timeout=timeout,
    )

    try:
        writer.write((query + "\r\n").encode("utf-8"))
        await writer.drain()

        raw = await asyncio.wait_for(reader.read(-1), timeout=timeout)
        return raw.decode("utf-8", errors="replace")

    finally:
        writer.close()

        try:
            await writer.wait_closed()
        except Exception:
            pass


class WHOISIntegration(AsyncBaseIntegration):
    """
    Pure-asyncio WHOIS client: queries whois.iana.org for the
    authoritative WHOIS server for the domain's TLD, then queries that
    server directly and parses the common registrar/date/nameserver
    fields out of the (largely unstandardized) raw response text.
    """

    source_name = "whois"

    def is_configured(self) -> bool:
        return True

    async def _query(self, target: str) -> IntegrationResult:

        domain = target.strip().lower().rstrip(".")
        timeout = settings.WHOIS_TIMEOUT_SECONDS

        try:
            iana_response = await _whois_query(_IANA_WHOIS_HOST, domain, timeout)

        except asyncio.TimeoutError as error:
            raise IntegrationTimeoutError(
                f"WHOIS referral lookup for '{domain}' timed out."
            ) from error

        except OSError as error:

            return IntegrationResult(
                source=self.source_name,
                status=ModuleResultStatus.FAILED,
                error_message=f"Could not reach IANA WHOIS server: {error}",
            )

        referral_match = _REFERRAL_PATTERN.search(iana_response)

        if not referral_match:

            return IntegrationResult(
                source=self.source_name,
                status=ModuleResultStatus.NOT_FOUND,
                data={
                    "domain": domain,
                    "whois_server": None,
                    "registered": False,
                },
                error_message="No authoritative WHOIS server found for this TLD.",
            )

        whois_server = referral_match.group(1)

        try:
            raw_record = await _whois_query(whois_server, domain, timeout)

        except asyncio.TimeoutError as error:
            raise IntegrationTimeoutError(
                f"WHOIS lookup for '{domain}' via {whois_server} timed out."
            ) from error

        except OSError as error:

            return IntegrationResult(
                source=self.source_name,
                status=ModuleResultStatus.FAILED,
                error_message=f"Could not reach WHOIS server {whois_server}: {error}",
            )

        if _looks_unregistered(raw_record):

            return IntegrationResult(
                source=self.source_name,
                status=ModuleResultStatus.NOT_FOUND,
                data={
                    "domain": domain,
                    "whois_server": whois_server,
                    "registered": False,
                },
            )

        fields = {
            key: match.group(1).strip()
            for key, pattern in _FIELD_PATTERNS.items()
            if (match := pattern.search(raw_record))
        }

        name_servers = sorted(
            {match.group(1).rstrip(".").lower() for match in _NAME_SERVER_PATTERN.finditer(raw_record)}
        )

        # Additive fields - none of these replace or rename an
        # existing key above.
        domain_statuses = sorted(
            {match.group(1).strip() for match in _ALL_DOMAIN_STATUS_PATTERN.finditer(raw_record)}
        )

        dnssec_match = _DNSSEC_PATTERN.search(raw_record)
        dnssec = dnssec_match.group(1).strip() if dnssec_match else None

        data = {
            "domain": domain,
            "whois_server": whois_server,
            "registered": True,
            "name_servers": name_servers,
            "domain_statuses": domain_statuses,
            "dnssec": dnssec,
            "domain_age_days": _domain_age_days(fields.get("creation_date")),
            **fields,
        }

        return IntegrationResult(
            source=self.source_name,
            status=ModuleResultStatus.SUCCESS,
            data=data,
            raw_response={"whois_text": raw_record[:8000]},
        )


def _looks_unregistered(raw_record: str) -> bool:

    markers = (
        "no match",
        "not found",
        "no data found",
        "no entries found",
        "status: free",
        "domain not found",
    )

    lowered = raw_record.lower()

    return any(marker in lowered for marker in markers)
