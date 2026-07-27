import dns.asyncresolver
import dns.exception
import dns.resolver

from backend.app.core.config import settings
from backend.app.integrations.base import AsyncBaseIntegration
from backend.app.integrations.base import IntegrationResult
from backend.app.integrations.exceptions import IntegrationTimeoutError
from backend.app.models.investigation import ModuleResultStatus


class DMARCIntegration(AsyncBaseIntegration):
    """
    Resolves the domain's DMARC policy record at _dmarc.{domain} (a
    dedicated TXT lookup - Milestone 4's DNSLookupIntegration only
    queries the bare domain's TXT records, which never includes this
    one) and parses its policy tags. DMARC tells receiving mail servers
    what to do with messages that fail SPF/DKIM alignment - its absence
    or a weak policy (p=none) is one of the most common indicators of
    an organization's mail domain being spoofable.
    """

    source_name = "dmarc"

    def is_configured(self) -> bool:
        return True

    async def _query(self, target: str) -> IntegrationResult:

        domain = target.strip().lower().rstrip(".")
        dmarc_host = f"_dmarc.{domain}"

        resolver = dns.asyncresolver.Resolver()
        resolver.timeout = settings.DNS_RESOLVER_TIMEOUT_SECONDS
        resolver.lifetime = settings.DNS_RESOLVER_TIMEOUT_SECONDS

        try:
            answer = await resolver.resolve(dmarc_host, "TXT")

        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):

            return IntegrationResult(
                source=self.source_name,
                status=ModuleResultStatus.NOT_FOUND,
                data={
                    "domain": domain,
                    "has_dmarc_record": False,
                    "raw_record": None,
                    "policy": None,
                },
            )

        except dns.exception.Timeout as error:
            raise IntegrationTimeoutError(str(error)) from error

        raw_records = [
            b"".join(record.strings).decode("utf-8", errors="replace")
            for record in answer
        ]

        dmarc_record = next(
            (r for r in raw_records if r.lower().startswith("v=dmarc1")),
            None,
        )

        if dmarc_record is None:

            return IntegrationResult(
                source=self.source_name,
                status=ModuleResultStatus.NOT_FOUND,
                data={
                    "domain": domain,
                    "has_dmarc_record": False,
                    "raw_record": None,
                    "policy": None,
                },
            )

        tags = _parse_dmarc_tags(dmarc_record)

        data = {
            "domain": domain,
            "has_dmarc_record": True,
            "raw_record": dmarc_record,
            "policy": tags.get("p"),
            "subdomain_policy": tags.get("sp"),
            "percentage_covered": tags.get("pct"),
            "alignment_mode_dkim": tags.get("adkim"),
            "alignment_mode_spf": tags.get("aspf"),
            "aggregate_report_addresses": _split_report_addresses(tags.get("rua")),
            "forensic_report_addresses": _split_report_addresses(tags.get("ruf")),
        }

        return IntegrationResult(
            source=self.source_name,
            status=ModuleResultStatus.SUCCESS,
            data=data,
        )


def _parse_dmarc_tags(record: str) -> dict[str, str]:

    tags: dict[str, str] = {}

    for segment in record.split(";"):

        segment = segment.strip()

        if not segment or "=" not in segment:
            continue

        key, _, value = segment.partition("=")
        tags[key.strip().lower()] = value.strip()

    return tags


def _split_report_addresses(value: str | None) -> list[str]:

    if not value:
        return []

    return [addr.strip().removeprefix("mailto:") for addr in value.split(",") if addr.strip()]
