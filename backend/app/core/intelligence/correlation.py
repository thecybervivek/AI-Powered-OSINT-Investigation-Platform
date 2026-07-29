"""
Relationship-typed correlation engine.

Builds on backend.app.utils.evidence_correlation (entity extraction -
already present/maintained in this shared baseline, left unmodified
here) by adding the relationship-CATEGORY semantics the architecture
spec calls for:

    Identity:        email <-> username <-> phone <-> social profile
    Infrastructure:  url <-> domain <-> dns <-> ip <-> asn
    Threat:          file <-> hash <-> malware <-> threat intel <-> url/domain/ip

CRITICAL SAFEGUARD: a shared identifier is evidence of a POSSIBLE
relationship, never proof of one - "same username on two platforms" is
NOT "same person". Every correlation this module returns carries
`asserts_identity=False` and a human-readable `caveat` explaining
exactly what was and wasn't established, specifically so no caller
(including Account 3's UI) can accidentally present a correlation as a
confirmed identity match without deliberately overriding that.
"""

from dataclasses import dataclass
from enum import Enum

from backend.app.utils.evidence_correlation import InvestigationRef
from backend.app.utils.evidence_correlation import find_shared_indicators


class RelationshipCategory(str, Enum):

    IDENTITY = "identity"
    INFRASTRUCTURE = "infrastructure"
    THREAT = "threat"
    UNKNOWN = "unknown"


_ENTITY_TYPE_TO_CATEGORY: dict[str, RelationshipCategory] = {
    "email": RelationshipCategory.IDENTITY,
    "username": RelationshipCategory.IDENTITY,
    "phone": RelationshipCategory.IDENTITY,
    "social_profile": RelationshipCategory.IDENTITY,
    "domain": RelationshipCategory.INFRASTRUCTURE,
    "ip": RelationshipCategory.INFRASTRUCTURE,
    "url": RelationshipCategory.INFRASTRUCTURE,
    "asn": RelationshipCategory.INFRASTRUCTURE,
    "dns": RelationshipCategory.INFRASTRUCTURE,
    "file_hash": RelationshipCategory.THREAT,
    "malware": RelationshipCategory.THREAT,
    "threat_intel": RelationshipCategory.THREAT,
}

_IDENTITY_CAVEAT = (
    "This is a shared identifier, not a confirmed identity match - the "
    "same username, email, or phone number appearing across "
    "investigations may belong to different people. Treat as a lead "
    "to verify, not a conclusion."
)

_INFRASTRUCTURE_CAVEAT = (
    "This is shared infrastructure (domain/IP/ASN), which can be "
    "legitimately shared by unrelated services (shared hosting, CDNs, "
    "cloud providers) - it is a lead for further investigation, not "
    "proof of a relationship between the underlying targets."
)

_THREAT_CAVEAT = (
    "This indicator has appeared across multiple threat-related "
    "investigations - a lead worth correlating with campaign/actor "
    "data, not by itself proof the investigations share a single "
    "source or actor."
)

_CATEGORY_CAVEATS = {
    RelationshipCategory.IDENTITY: _IDENTITY_CAVEAT,
    RelationshipCategory.INFRASTRUCTURE: _INFRASTRUCTURE_CAVEAT,
    RelationshipCategory.THREAT: _THREAT_CAVEAT,
    RelationshipCategory.UNKNOWN: "Shared indicator of an unclassified type - review manually.",
}


def _category_for_entity_type(entity_type: str) -> RelationshipCategory:
    return _ENTITY_TYPE_TO_CATEGORY.get(entity_type, RelationshipCategory.UNKNOWN)


@dataclass(frozen=True)
class TypedCorrelation:

    shared_indicator: str
    entity_type: str
    relationship_category: RelationshipCategory
    investigation_count: int
    investigations: list[dict]
    asserts_identity: bool
    caveat: str

    def to_dict(self) -> dict:

        return {
            "shared_indicator": self.shared_indicator,
            "entity_type": self.entity_type,
            "relationship_category": self.relationship_category.value,
            "investigation_count": self.investigation_count,
            "investigations": self.investigations,
            "asserts_identity": self.asserts_identity,
            "caveat": self.caveat,
        }


def correlate(investigations: list[InvestigationRef]) -> list[TypedCorrelation]:
    """
    Runs the existing entity-level correlation and classifies each
    result by relationship category, attaching the appropriate caveat.
    `asserts_identity` is ALWAYS False - this function only ever
    reports that a shared identifier exists, never that two
    investigations are confirmed to be about the same real-world
    person, host, or actor.
    """

    raw_correlations = find_shared_indicators(investigations)

    typed = []

    for correlation in raw_correlations:

        category = _category_for_entity_type(correlation["entity_type"])

        typed.append(
            TypedCorrelation(
                shared_indicator=correlation["shared_indicator"],
                entity_type=correlation["entity_type"],
                relationship_category=category,
                investigation_count=correlation["investigation_count"],
                investigations=correlation["investigations"],
                asserts_identity=False,
                caveat=_CATEGORY_CAVEATS[category],
            )
        )

    return typed


def correlate_by_category(
    investigations: list[InvestigationRef],
    category: RelationshipCategory,
) -> list[TypedCorrelation]:
    """Convenience filter - e.g. only IDENTITY correlations for a person-focused view."""

    return [c for c in correlate(investigations) if c.relationship_category == category]
