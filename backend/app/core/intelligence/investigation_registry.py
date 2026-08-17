"""
Investigation Type Registry - single source of truth.

Today, adding a module means touching: the backend Python enum, a
PostgreSQL native-enum migration, frontend TypeScript unions, the
"New Investigation" modal, service routing, and labels/descriptions -
independently, by hand, with no single place that can't drift out of
sync. This registry is that single place.

CRITICAL FINDING FROM AUDITING THIS BASELINE: every investigation-type
enum-value migration added in this project so far (Milestone 9's
'file', 'social_media', 'breach', 'threat_intelligence', 'malware',
'risk_assessment' migrations) added the WRONG PostgreSQL enum label.
SQLAlchemy's native `Enum` type persists a Python Enum member's `.name`
(e.g. "FILE") by default, NOT its `.value` (e.g. "file"), unless the
column is built with `values_callable`. Every one of those migrations
ran `ALTER TYPE investigationtype ADD VALUE 'file'` (lowercase) - a
label PostgreSQL would never actually be asked for, since SQLAlchemy
sends "FILE". A later migration in this baseline
(e7b34217b5d9_fix_investigation_type_enum_values.py, apparently from
Account 1) already patched this by adding the correct uppercase labels
alongside the incorrect lowercase ones it left in place.

This registry - combined with the migration that converts
investigation_type from a native Postgres ENUM to a plain VARCHAR - is
the actual fix: once the column is a plain string, adding a new
investigation type is a one-line change to this file, with NO database
migration required at all, and the enum-name-vs-value footgun stops
being possible by construction. Per Phase 1B's explicit instruction,
that architecture is NOT touched again here - this pass only refines
what the registry represents, not how it persists.

PHASE 1B AUDIT FINDING (this pass): the previous registry entry for
"metadata" set implementation_state="partial", which implies SOME
backend workflow exists. It does not: there is no metadata_service.py,
no api/v1/endpoints/metadata.py, and no router.py registration for it -
confirmed by grepping the entire backend/ tree and cross-checking
router.py's literal `include_router(...)` calls. The frontend's own
investigationTypes.config.ts already independently reached the same
conclusion (`available: false, unavailableReason: "Not yet available
as a standalone investigation type."`). This pass corrects
implementation_state to "planned" and adds the explicit
availability/unavailable_reason contract described below so this
class of drift is machine-checkable going forward instead of
independently re-discovered by each track.
"""

from dataclasses import dataclass
from dataclasses import field
from enum import Enum


class Availability(str, Enum):
    """
    The single field a client actually needs to decide "can I use this
    right now, and if not, why". Always DERIVED from the other truth
    fields on InvestigationTypeDefinition (see `availability` property
    below) rather than set independently - so it can never drift from
    implementation_state/api_state/provider_state the way a manually
    maintained boolean could.
    """

    AVAILABLE = "available"
    EXPERIMENTAL = "experimental"
    UNAVAILABLE = "unavailable"
    COMING_SOON = "coming_soon"


@dataclass(frozen=True)
class InvestigationTypeDefinition:

    identifier: str  # must match InvestigationType.<MEMBER>.value exactly
    label: str
    category: str  # e.g. "identity", "infrastructure", "threat", "risk"
    description: str
    icon: str
    input_type: str  # "username" | "email" | "domain_or_ip" | "url" | "phone" | "hash" | "file" | "investigation_id_list"
    validation_hint: str

    # Coarse UI-rendering hint, deliberately using the SAME vocabulary
    # already established independently by
    # frontend/src/components/investigations/investigationTypes.config.ts
    # (its `InvestigationInputMode` union: "text" | "file" | "image" |
    # "composite"). `input_type` above stays the richer backend-owned
    # semantic detail (e.g. "domain_or_ip", "hash"); `input_mode` is
    # the one field a client needs to pick which input control to
    # render, so this contract can fully replace that frontend file's
    # hand-maintained `inputMode` once Account 3 wires it up - see
    # Phase 1B's delivery notes for why "file" and "image" must stay
    # distinct here even though both accept an upload.
    input_mode: str = "text"  # "text" | "file" | "image" | "composite"

    # The literal prefix this type's router is mounted under in
    # api/v1/router.py (e.g. "/investigations/ip"), or None when no
    # router exists at all. This is the field
    # tests/test_registry_router_reality.py checks against router.py's
    # actual source text - a registry entry claiming availability
    # without a real mounted route is exactly the "fake or misleading
    # availability" this task exists to catch.
    router_prefix: str | None = None

    supported_capabilities: tuple[str, ...] = field(default_factory=tuple)

    # Independently trackable maturity signals - the whole point being
    # that "UI says supported" and "this actually works" can now be
    # compared instead of assumed equal.
    implementation_state: str = "implemented"  # implemented | partial | planned
    api_state: str = "untested"                # tested | untested | broken
    ui_state: str = "unknown"                   # stable | experimental | missing | unknown
    provider_state: str = "unknown"              # full | partial | none | unknown
    production_status: str = "experimental"      # production | experimental | beta | deprecated

    @property
    def availability(self) -> Availability:
        """
        Derived, not stored - see the Availability docstring above.
        Order matters: implementation gates everything else, since an
        untested API on top of a partial implementation is still
        fundamentally "not implemented", not merely "not tested".
        """

        if self.implementation_state == "planned":
            return Availability.COMING_SOON

        if self.implementation_state != "implemented":
            return Availability.UNAVAILABLE

        if self.router_prefix is None:
            # Implementation claims complete but nothing is actually
            # mounted - this should never happen if the registry is
            # kept honest, but if it ever does, report UNAVAILABLE
            # rather than silently trusting the implementation_state
            # label alone.
            return Availability.UNAVAILABLE

        if self.api_state != "tested":
            return Availability.UNAVAILABLE

        if self.production_status == "experimental":
            return Availability.EXPERIMENTAL

        return Availability.AVAILABLE

    @property
    def unavailable_reason(self) -> str | None:
        """None when availability is AVAILABLE or EXPERIMENTAL - a reason only makes sense for the other two states."""

        if self.availability == Availability.COMING_SOON:
            return f"'{self.label}' is planned but not yet implemented as a standalone investigation type."

        if self.availability == Availability.UNAVAILABLE:

            if self.router_prefix is None:
                return f"'{self.label}' has no backend endpoint registered yet."

            if self.implementation_state != "implemented":
                return f"'{self.label}' implementation is '{self.implementation_state}', not yet complete."

            if self.api_state != "tested":
                return f"'{self.label}' API has not been verified end-to-end yet (api_state='{self.api_state}')."

        return None

    def to_dict(self) -> dict:

        return {
            "identifier": self.identifier,
            "label": self.label,
            "category": self.category,
            "description": self.description,
            "icon": self.icon,
            "input_type": self.input_type,
            "input_mode": self.input_mode,
            "validation_hint": self.validation_hint,
            "router_prefix": self.router_prefix,
            "supported_capabilities": list(self.supported_capabilities),
            "implementation_state": self.implementation_state,
            "api_state": self.api_state,
            "ui_state": self.ui_state,
            "provider_state": self.provider_state,
            "production_status": self.production_status,
            "availability": self.availability.value,
            "unavailable_reason": self.unavailable_reason,
        }


# NOTE: `implementation_state`/`api_state`/`ui_state`/`provider_state`/
# `production_status` below reflect what Account 2's track can
# actually verify from the backend/service code audited in this pass.
# Account 3 owns UI truth and Account 1 owns deployment truth - both
# should correct their respective fields here rather than maintaining
# a second, separate source for the same facts. See the integration
# notes in the delivery summary.
INVESTIGATION_TYPE_REGISTRY: dict[str, InvestigationTypeDefinition] = {
    d.identifier: d
    for d in [
        InvestigationTypeDefinition(
            identifier="username",
            label="Username Intelligence",
            category="identity",
            description="Public profile existence across social/dev/media platforms.",
            icon="user-search",
            input_type="username",
            input_mode="text",
            router_prefix="/investigations/username",
            validation_hint="Letters, numbers, dots, underscores, hyphens only.",
            supported_capabilities=("profile_discovery", "platform_presence"),
            api_state="tested",
            provider_state="full",
            production_status="production",
        ),
        InvestigationTypeDefinition(
            identifier="email",
            label="Email Intelligence",
            category="identity",
            description="Reputation, breach history, disposable-address, and MX checks.",
            icon="mail-search",
            input_type="email",
            input_mode="text",
            router_prefix="/investigations/email",
            validation_hint="A valid email address.",
            supported_capabilities=(
                "reputation", "breach_history", "mx_lookup", "disposable_detection",
                "account_presence", "identity_correlation", "ghunt",
            ),
            api_state="tested",
            provider_state="partial",
            production_status="production",
        ),
        InvestigationTypeDefinition(
            identifier="domain",
            label="Domain Intelligence",
            category="infrastructure",
            description="WHOIS/RDAP, DNS, email security posture, TLS certificate, technology detection, subdomains, infrastructure, and threat intelligence.",
            icon="globe",
            input_type="domain_or_ip",
            input_mode="text",
            router_prefix="/investigations/domain",
            validation_hint="A domain name or IP address.",
            supported_capabilities=(
                "whois", "dns", "ssl", "technology_detection",
                "email_security_posture", "dnssec", "certificate_transparency",
                "subdomain_discovery", "asn_lookup", "ip_geolocation",
                "reverse_dns", "threat_intelligence",
            ),
            api_state="tested",
            provider_state="full",
            production_status="production",
        ),
        InvestigationTypeDefinition(
            identifier="ip_address",
            label="IP Intelligence",
            category="infrastructure",
            description="Geolocation, ASN, and abuse/reputation checks.",
            icon="server",
            input_type="domain_or_ip",
            input_mode="text",
            router_prefix="/investigations/ip",
            validation_hint="An IPv4/IPv6 address or a domain to resolve.",
            supported_capabilities=("geolocation", "asn", "reputation"),
            api_state="tested",
            provider_state="partial",
            production_status="production",
        ),
        InvestigationTypeDefinition(
            identifier="dns",
            label="DNS Intelligence",
            category="infrastructure",
            description="Subdomain enumeration, DMARC/SPF analysis, passive DNS.",
            icon="network",
            input_type="domain_or_ip",
            input_mode="text",
            router_prefix="/investigations/dns-intelligence",
            validation_hint="A bare domain name.",
            supported_capabilities=("subdomain_enum", "spf", "dmarc", "passive_dns"),
            api_state="tested",
            provider_state="partial",
            production_status="beta",
        ),
        InvestigationTypeDefinition(
            identifier="url",
            label="URL Intelligence",
            category="infrastructure",
            description="Domain context plus VirusTotal/URLScan verdicts for a specific link.",
            icon="link",
            input_type="url",
            input_mode="text",
            router_prefix="/investigations/url",
            validation_hint="A full URL including http(s)://.",
            supported_capabilities=("reputation", "sandbox_analysis"),
            api_state="tested",
            provider_state="partial",
            production_status="production",
        ),
        InvestigationTypeDefinition(
            identifier="phone",
            label="Phone Intelligence",
            category="identity",
            description="Validation, carrier/country/region/timezone lookup, E.164 formatting.",
            icon="phone",
            input_type="phone",
            input_mode="text",
            router_prefix="/investigations/phone",
            validation_hint="Include country code, e.g. +1...",
            supported_capabilities=("validation", "carrier_lookup", "breach_history"),
            api_state="tested",
            provider_state="partial",
            production_status="beta",
        ),
        InvestigationTypeDefinition(
            identifier="metadata",
            label="File Metadata",
            category="file",
            description="EXIF/document metadata extraction as a standalone investigation type.",
            icon="file-text",
            input_type="file",
            input_mode="file",
            router_prefix=None,  # no metadata_service.py / endpoint / router.py entry exists
            validation_hint="Upload a file.",
            supported_capabilities=(),
            implementation_state="planned",  # was "partial" - corrected: zero workflow exists, see module docstring
            api_state="untested",
            provider_state="unknown",
            production_status="experimental",
        ),
        InvestigationTypeDefinition(
            identifier="reverse_image",
            label="Reverse Image Intelligence",
            category="file",
            description="Perceptual hashing and near-duplicate detection against your own history.",
            icon="image-search",
            input_type="image",
            input_mode="image",
            router_prefix="/investigations/reverse-image",
            validation_hint="Upload an image file.",
            supported_capabilities=("perceptual_hash", "duplicate_detection"),
            api_state="tested",
            ui_state="experimental",
            provider_state="partial",
            production_status="experimental",
        ),
        InvestigationTypeDefinition(
            identifier="file",
            label="File Intelligence",
            category="file",
            description="Hashing, metadata, YARA scanning, and hash-reputation lookups.",
            icon="file-search",
            input_type="file",
            input_mode="file",
            router_prefix="/investigations/file",
            validation_hint="Upload any file for analysis.",
            supported_capabilities=("hashing", "yara", "reputation"),
            api_state="tested",
            provider_state="partial",
            production_status="beta",
        ),
        InvestigationTypeDefinition(
            identifier="social_media",
            label="Social Media Intelligence",
            category="identity",
            description="Public profile discovery and username correlation across named platforms.",
            icon="users",
            input_type="username",
            input_mode="text",
            router_prefix="/investigations/social-media",
            validation_hint="A primary username, optionally with related aliases.",
            supported_capabilities=("profile_discovery", "username_correlation"),
            api_state="tested",
            provider_state="full",
            production_status="beta",
        ),
        InvestigationTypeDefinition(
            identifier="breach",
            label="Breach Intelligence",
            category="identity",
            description="Breach timeline, exposed emails/domains, password exposure status.",
            icon="shield-alert",
            input_type="email",
            input_mode="text",
            router_prefix="/investigations/breach",
            validation_hint="An email address or a bare domain.",
            supported_capabilities=("breach_timeline", "password_exposure"),
            api_state="tested",
            provider_state="partial",
            production_status="beta",
        ),
        InvestigationTypeDefinition(
            identifier="threat_intelligence",
            label="Threat Intelligence",
            category="threat",
            description="Host intelligence, threat reputation, and historical DNS across 5 providers.",
            icon="crosshair",
            input_type="domain_or_ip",
            input_mode="text",
            router_prefix="/investigations/threat-intelligence",
            validation_hint="An IP address or a domain.",
            supported_capabilities=("host_intel", "threat_reputation", "historical_dns"),
            api_state="tested",
            provider_state="partial",
            production_status="beta",
        ),
        InvestigationTypeDefinition(
            identifier="malware",
            label="Malware Intelligence",
            category="threat",
            description="Family lookup, classification, campaign correlation, IOC correlation.",
            icon="bug",
            input_type="hash",
            input_mode="text",
            router_prefix="/investigations/malware",
            validation_hint="An MD5, SHA1, or SHA256 hash.",
            supported_capabilities=("family_lookup", "classification", "ioc_correlation"),
            api_state="tested",
            provider_state="partial",
            production_status="beta",
        ),
        InvestigationTypeDefinition(
            identifier="risk_assessment",
            label="Composite Risk Assessment",
            category="risk",
            description="Combines multiple past investigations into one composite assessment.",
            icon="gauge",
            input_type="investigation_id_list",
            input_mode="composite",
            router_prefix="/investigations/risk-assessment",
            validation_hint="2-20 of your own past investigation IDs.",
            supported_capabilities=("composite_scoring", "evidence_correlation"),
            api_state="tested",
            provider_state="none",  # reuses existing evidence, runs no providers of its own
            production_status="experimental",
        ),
    ]
}


def get_definition(identifier: str) -> InvestigationTypeDefinition | None:
    return INVESTIGATION_TYPE_REGISTRY.get(identifier)


def list_definitions() -> list[InvestigationTypeDefinition]:
    return list(INVESTIGATION_TYPE_REGISTRY.values())


def list_by_category(category: str) -> list[InvestigationTypeDefinition]:
    return [d for d in INVESTIGATION_TYPE_REGISTRY.values() if d.category == category]


def is_registered(identifier: str) -> bool:
    return identifier in INVESTIGATION_TYPE_REGISTRY


def registry_as_json_export() -> list[dict]:
    """
    What a frontend (Account 3) or a docs/release-audit script would
    consume - one flat, serializable list, so the TypeScript union, the
    "New Investigation" modal, and any README/capability audit can all
    be generated FROM this instead of hand-maintained separately.
    """

    return [d.to_dict() for d in list_definitions()]
