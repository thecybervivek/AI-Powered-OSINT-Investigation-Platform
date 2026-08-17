"""
Tests for Domain Intelligence's Email Security Posture (SPF/DMARC/
MTA-STS/TLS-RPT/bounded-DKIM) and the DNSSEC presence / SRV additions
to DNS Lookup (spec sections 5 and 6).
"""

import asyncio
from unittest.mock import AsyncMock

import dns.resolver

from backend.app.integrations.domain.dns_integration import DNSLookupIntegration
from backend.app.integrations.domain.email_security_integration import EmailSecurityIntegration
from backend.app.integrations.domain.email_security_integration import _extract_tag
from backend.app.models.investigation import ModuleResultStatus


class _FakeTXTRecord:
    def __init__(self, text: str):
        self.strings = [text.encode("utf-8")]


class _FakeTXTAnswer:
    """Mimics a dnspython TXT answer: iterable of records with `.strings`."""

    def __init__(self, texts: list[str]):
        self._texts = texts

    def __iter__(self):
        return iter(_FakeTXTRecord(t) for t in self._texts)


def _resolver_returning(mapping: dict[tuple[str, str], list[str]]):
    """
    Builds a fake resolver whose `.resolve(name, record_type)` returns
    a canned TXT answer for a mapped (name, record_type) pair, or
    raises NXDOMAIN otherwise - the shape both DNSLookupIntegration and
    EmailSecurityIntegration actually call.
    """

    async def _resolve(name, record_type):
        key = (name.rstrip("."), record_type)

        if key not in mapping:
            raise dns.resolver.NXDOMAIN()

        return _FakeTXTAnswer(mapping[key])

    resolver = AsyncMock()
    resolver.resolve = AsyncMock(side_effect=_resolve)
    return resolver


# ==========================================================
# _extract_tag (pure function, no mocking needed)
# ==========================================================


def test_extract_tag_pulls_dmarc_policy():
    record = "v=DMARC1; p=reject; rua=mailto:agg@example.com"
    assert _extract_tag(record, "p") == "reject"


def test_extract_tag_returns_none_when_absent():
    assert _extract_tag("v=DMARC1; rua=mailto:agg@example.com", "p") is None


def test_extract_tag_returns_none_for_no_record():
    assert _extract_tag(None, "p") is None


# ==========================================================
# EmailSecurityIntegration
# ==========================================================


def test_email_security_detects_present_spf_and_dmarc(monkeypatch):

    integration = EmailSecurityIntegration()

    resolver = _resolver_returning({
        ("example.com", "TXT"): ["v=spf1 include:_spf.example.com ~all"],
        ("_dmarc.example.com", "TXT"): ["v=DMARC1; p=reject"],
    })

    monkeypatch.setattr(
        "backend.app.integrations.domain.email_security_integration.dns.asyncresolver.Resolver",
        lambda: resolver,
    )

    result = asyncio.run(integration._query("example.com"))

    assert result.status == ModuleResultStatus.SUCCESS
    assert result.data["spf"]["present"] is True
    assert result.data["dmarc"]["present"] is True
    assert result.data["dmarc"]["policy"] == "reject"


def test_email_security_absence_is_reported_not_errored(monkeypatch):
    """
    Absence of SPF/DMARC/MTA-STS/TLS-RPT is the normal case for most
    domains - must be a plain SUCCESS result with present=False, never
    FAILED/SKIPPED (spec section 6 - "do not automatically label weak
    configuration as malicious", which starts with not treating
    absence as an error in the first place).
    """

    integration = EmailSecurityIntegration()

    resolver = _resolver_returning({})  # everything NXDOMAIN

    monkeypatch.setattr(
        "backend.app.integrations.domain.email_security_integration.dns.asyncresolver.Resolver",
        lambda: resolver,
    )

    result = asyncio.run(integration._query("nospf-example.com"))

    assert result.status == ModuleResultStatus.SUCCESS
    assert result.data["spf"]["present"] is False
    assert result.data["dmarc"]["present"] is False
    assert result.data["mta_sts"]["present"] is False
    assert result.data["tls_rpt"]["present"] is False


def test_email_security_dkim_check_is_bounded_and_labeled_non_exhaustive(monkeypatch):

    integration = EmailSecurityIntegration()

    resolver = _resolver_returning({})

    monkeypatch.setattr(
        "backend.app.integrations.domain.email_security_integration.dns.asyncresolver.Resolver",
        lambda: resolver,
    )

    result = asyncio.run(integration._query("example.com"))

    # Bounded: a small, fixed number of selectors, not an open-ended scan.
    assert len(result.data["dkim"]["selectors_checked"]) <= 10
    assert "note" in result.data["dkim"]
    assert "not" in result.data["dkim"]["note"].lower()


# ==========================================================
# DNS Lookup: SRV + DNSSEC presence
# ==========================================================


def test_srv_added_to_queried_record_types():
    from backend.app.integrations.domain.dns_integration import _RECORD_TYPES
    assert "SRV" in _RECORD_TYPES


def test_dnssec_presence_true_when_ds_and_dnskey_both_exist():

    resolver = _resolver_returning({
        ("example.com", "DS"): ["fake-ds-record"],
        ("example.com", "DNSKEY"): ["fake-dnskey-record"],
    })

    presence = asyncio.run(
        DNSLookupIntegration._check_dnssec_presence(resolver, "example.com")
    )

    assert presence["ds_present"] is True
    assert presence["dnskey_present"] is True
    assert presence["signed"] is True


def test_dnssec_presence_false_when_absent_not_an_error():
    """
    Most domains do not have DNSSEC deployed - absence must be a plain
    fact (signed=False), never surfaced as a failure of the DNS lookup
    as a whole.
    """

    resolver = _resolver_returning({})  # NXDOMAIN for both DS and DNSKEY

    presence = asyncio.run(
        DNSLookupIntegration._check_dnssec_presence(resolver, "example.com")
    )

    assert presence["ds_present"] is False
    assert presence["dnskey_present"] is False
    assert presence["signed"] is False
