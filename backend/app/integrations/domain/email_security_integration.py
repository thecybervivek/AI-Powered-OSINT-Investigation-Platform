"""
Email Security Posture (spec section 6).

Answers: "what does this domain's own DNS say about how it wants
inbound mail verification / outbound mail authentication to be
handled?" - entirely passive TXT record lookups, no message is ever
sent and no mail server is contacted.

Deliberately narrow on DKIM: DKIM selectors are chosen by whoever
configured the domain's mail sender and are NOT discoverable from DNS
without already knowing (or guessing) one. Brute-forcing selectors is
explicitly out of scope (spec: "Do not brute-force thousands of
selectors"). This checks a small, fixed list of the handful of
selector names common enough that many real-world OSINT/email-security
tools check them by default (the sending platform's own default, or a
generic placeholder) - explicitly NOT exhaustive, and every result
says so.
"""

import dns.asyncresolver
import dns.exception
import dns.resolver

from backend.app.core.config import settings
from backend.app.integrations.base import AsyncBaseIntegration
from backend.app.integrations.base import IntegrationResult
from backend.app.integrations.exceptions import IntegrationTimeoutError
from backend.app.models.investigation import ModuleResultStatus

# Bounded, explicitly non-exhaustive. Each is a real default selector
# used by a specific, common sending platform/convention - not a
# guessed wordlist.
_COMMON_DKIM_SELECTORS = ("default", "selector1", "selector2", "google", "k1", "s1")


async def _lookup_txt(resolver, name: str) -> list[str] | None:
    """
    Returns the list of TXT record strings at `name`, or None if the
    name has no TXT record / doesn't exist. Never raises for the
    "not present" case - that's the expected, common outcome for most
    of these checks on most domains.
    """

    try:
        answer = await resolver.resolve(name, "TXT")
        return [
            b"".join(record.strings).decode("utf-8", errors="replace")
            for record in answer
        ]

    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return None

    except dns.exception.Timeout as error:
        raise IntegrationTimeoutError(str(error)) from error


class EmailSecurityIntegration(AsyncBaseIntegration):
    """
    SPF (TXT at the domain itself), DMARC (TXT at _dmarc.<domain>),
    MTA-STS (TXT at _mta-sts.<domain>), TLS-RPT (TXT at
    _smtp._tls.<domain>), and a bounded, explicitly-non-exhaustive DKIM
    selector presence check. Absence of any of these is normal for the
    large majority of domains and is reported as a plain fact, not an
    error - see EmailIntelligenceService's identical MX-absence
    precedent for why this must never be scored as risk on its own
    (spec section 17 / this module's own section 6).
    """

    source_name = "email_security"

    def is_configured(self) -> bool:
        return True

    async def _query(self, target: str) -> IntegrationResult:

        domain = target.strip().lower().rstrip(".")

        resolver = dns.asyncresolver.Resolver()
        resolver.timeout = settings.DNS_RESOLVER_TIMEOUT_SECONDS
        resolver.lifetime = settings.DNS_RESOLVER_TIMEOUT_SECONDS

        spf_txts = await _lookup_txt(resolver, domain)
        spf_record = next(
            (t for t in (spf_txts or []) if t.lower().startswith("v=spf1")), None
        )

        dmarc_txts = await _lookup_txt(resolver, f"_dmarc.{domain}")
        dmarc_record = next(
            (t for t in (dmarc_txts or []) if t.lower().startswith("v=dmarc1")), None
        )
        dmarc_policy = _extract_tag(dmarc_record, "p")

        mta_sts_txts = await _lookup_txt(resolver, f"_mta-sts.{domain}")
        mta_sts_record = next(
            (t for t in (mta_sts_txts or []) if t.lower().startswith("v=stsv1")), None
        )

        tls_rpt_txts = await _lookup_txt(resolver, f"_smtp._tls.{domain}")
        tls_rpt_record = next(
            (t for t in (tls_rpt_txts or []) if t.lower().startswith("v=tlsrptv1")),
            None,
        )

        dkim_checked: list[str] = []
        dkim_found: list[dict] = []

        for selector in _COMMON_DKIM_SELECTORS:

            dkim_checked.append(selector)
            dkim_txts = await _lookup_txt(resolver, f"{selector}._domainkey.{domain}")

            if dkim_txts:
                dkim_found.append({"selector": selector, "record": dkim_txts[0]})

        data = {
            "domain": domain,
            "spf": {
                "present": spf_record is not None,
                "record": spf_record,
            },
            "dmarc": {
                "present": dmarc_record is not None,
                "record": dmarc_record,
                "policy": dmarc_policy,
            },
            "mta_sts": {"present": mta_sts_record is not None, "record": mta_sts_record},
            "tls_rpt": {"present": tls_rpt_record is not None, "record": tls_rpt_record},
            "dkim": {
                "selectors_checked": dkim_checked,
                "selectors_found": dkim_found,
                "note": (
                    "Only a small, fixed set of common default selector "
                    "names was checked - this is NOT exhaustive. A "
                    "domain can have DKIM fully configured under a "
                    "selector not in this list and still show "
                    "selectors_found=[] here."
                ),
            },
        }

        return IntegrationResult(
            source=self.source_name,
            status=ModuleResultStatus.SUCCESS,
            data=data,
        )


def _extract_tag(record: str | None, tag: str) -> str | None:
    """Pulls a `tag=value` component out of a DMARC/SPF-style TXT record."""

    if not record:
        return None

    for part in record.split(";"):
        part = part.strip()
        if part.lower().startswith(f"{tag}="):
            return part.split("=", 1)[1].strip()

    return None
