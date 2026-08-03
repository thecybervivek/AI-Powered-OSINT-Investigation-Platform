"""
Qualitative threat assessment (replaces numeric Risk Score/Risk Level
for IP Address Investigation).

A 0-100 "risk score" implies a precision passive OSINT cannot actually
deliver, especially when reputation providers are unconfigured - a
score of 0 in that situation looks identical to "confirmed clean" when
it actually means "we never checked". This module produces one of five
explicit, evidence-grounded verdicts instead, and an analyst-style
summary that says plainly what was and wasn't checked.
"""

from dataclasses import dataclass
from dataclasses import field
from enum import Enum


class ThreatAssessment(str, Enum):

    MALICIOUS_DETECTED = "malicious_detected"
    SUSPICIOUS_DETECTED = "suspicious_detected"
    NO_MALICIOUS_EVIDENCE = "no_malicious_evidence"
    INCOMPLETE = "incomplete"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"


_DISPLAY_LABEL = {
    ThreatAssessment.MALICIOUS_DETECTED: "Malicious indicators detected",
    ThreatAssessment.SUSPICIOUS_DETECTED: "Suspicious indicators detected",
    ThreatAssessment.NO_MALICIOUS_EVIDENCE: "No malicious evidence detected",
    ThreatAssessment.INCOMPLETE: "Threat assessment incomplete",
    ThreatAssessment.INSUFFICIENT_EVIDENCE: "Insufficient evidence",
}


def display_label(assessment: ThreatAssessment) -> str:
    return _DISPLAY_LABEL[assessment]


@dataclass(frozen=True)
class ReputationFinding:
    """One reputation provider's contribution, already normalized to malicious/suspicious/clean/unavailable."""

    provider: str
    configured: bool
    reached: bool  # False if configured but the call itself failed (network/timeout/auth)
    malicious: bool = False
    suspicious: bool = False
    detail: str = ""  # e.g. "12 vendors flagged malicious", "confidence 87%"


def determine_threat_assessment(findings: list[ReputationFinding]) -> ThreatAssessment:
    """
    MALICIOUS_DETECTED / SUSPICIOUS_DETECTED only when a configured,
    successfully-reached provider actually reported it - never inferred
    from absence. INSUFFICIENT_EVIDENCE when nothing is configured at
    all (there is no basis for any conclusion, positive or negative).
    INCOMPLETE when some providers ran clean but others that WERE
    configured failed to respond (so "clean" can't be stated with full
    confidence). NO_MALICIOUS_EVIDENCE only when every configured
    provider was successfully reached and none flagged anything.
    """

    configured = [f for f in findings if f.configured]

    if not configured:
        return ThreatAssessment.INSUFFICIENT_EVIDENCE

    if any(f.malicious for f in configured if f.reached):
        return ThreatAssessment.MALICIOUS_DETECTED

    if any(f.suspicious for f in configured if f.reached):
        return ThreatAssessment.SUSPICIOUS_DETECTED

    unreached = [f for f in configured if not f.reached]

    if unreached:
        return ThreatAssessment.INCOMPLETE

    return ThreatAssessment.NO_MALICIOUS_EVIDENCE


def build_analyst_summary(
    *,
    target: str,
    resolved_ip: str,
    is_public: bool,
    ip_category_guidance: str | None,
    network_facts: list[str],
    reverse_dns_fact: str | None,
    threat_assessment: ThreatAssessment,
    unavailable_providers: list[str],
    threat_notes: list[str],
) -> str:
    """
    Builds the multi-line analyst-style summary described in the spec
    (e.g. "Public IP successfully analyzed. ASN information was
    retrieved. ...") instead of a single generic sentence - each line
    states one concrete, verifiable fact about what was/wasn't checked.
    """

    lines: list[str] = []

    if not is_public:
        lines.append(ip_category_guidance or f"'{resolved_ip}' is not a publicly routable address.")
        return " ".join(lines)

    lines.append(
        f"Public IP successfully analyzed."
        if target == resolved_ip
        else f"'{target}' resolved to public IP {resolved_ip} and was successfully analyzed."
    )

    lines.extend(network_facts)

    if reverse_dns_fact:
        lines.append(reverse_dns_fact)

    if unavailable_providers:
        lines.append(
            "No threat intelligence providers were configured."
            if len(unavailable_providers) >= 4
            else f"Some threat intelligence providers were unavailable: {', '.join(unavailable_providers)}."
        )

    if threat_notes:
        lines.extend(threat_notes)

    elif threat_assessment == ThreatAssessment.NO_MALICIOUS_EVIDENCE:
        lines.append("No malicious indicators were observed from the available evidence.")

    if threat_assessment == ThreatAssessment.INSUFFICIENT_EVIDENCE:
        lines.append("No definitive security conclusion can be made without configured threat intelligence providers.")

    elif threat_assessment == ThreatAssessment.INCOMPLETE:
        lines.append("Some threat intelligence providers did not respond, so a complete security conclusion cannot be made.")

    return " ".join(lines)
