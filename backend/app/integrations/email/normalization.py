"""
Cross-provider normalization for Email Account & Social Presence.

Architecturally mirrors integrations/username/normalization.py: this
is the ONLY place that interprets "what does it mean when providers
agree/disagree about a platform", merging AccountPresenceIntegration's
per-platform checks (see checkers/) - and, where available,
GravatarIntegration's own result, since Gravatar is a legitimate
account-presence signal too - into one canonical, deduplicated finding
per platform with full provenance.

Nothing here computes or contributes to risk_score/risk_level - see
email_service.py's docstring: account presence is discoverability, not
a security finding, and must never affect risk.
"""

from dataclasses import dataclass

from backend.app.models.investigation import ModuleResultStatus

# Engine-level statuses that mean "this engine's own aggregate verdict
# is trustworthy" - used only for Gravatar below, which reports a
# single confirmed/not_found signal per run (so its own status is a
# meaningful gate). account_presence is different: it's one engine
# sweeping many independent platforms in a single run, so its
# per-platform rows are gated on having actual structured results
# instead (see normalize_and_correlate) - not on its own aggregate
# ModuleResultStatus, which must never cause 15 real platform results
# to be silently discarded.
_CONTRIBUTING_ENGINE_STATUSES = {
    ModuleResultStatus.SUCCESS,
    ModuleResultStatus.NOT_FOUND,
}

# Per-platform-row states (AccountPresenceState values, as strings)
# that mean "we got a real, conclusive answer" - anything else
# (unknown/blocked/rate_limited/failed) is folded into "unable to
# verify" at the UI-grouping level, while the specific state is still
# preserved in provider_evidence for audit.
_CONFIRMED_STATES = {"confirmed"}
_NOT_FOUND_STATES = {"not_found"}


@dataclass
class ProviderEvidence:

    provider: str
    state: str  # raw AccountPresenceState value, e.g. "blocked"
    http_status: int | None
    profile_url: str | None
    provider_reason: str | None

    def to_dict(self) -> dict:
        return {
            "provider": self.provider,
            "state": self.state,
            "http_status": self.http_status,
            "profile_url": self.profile_url,
            "provider_reason": self.provider_reason,
        }


@dataclass
class CanonicalFinding:
    """
    One deduplicated, cross-provider finding for a single platform.

    status:
        "confirmed"   - at least one provider confirmed, no provider
                        contradicted it.
        "not_found"   - at least one provider confirmed absence, no
                        provider confirmed presence.
        "conflict"    - providers disagree (one confirmed, another
                        confirmed absence) - never silently resolved
                        to either side.
        "unknown"     - every contributing provider that checked this
                        platform was inconclusive (blocked, rate
                        limited, failed, or otherwise unknown).
    """

    platform: str
    category: str | None
    profile_url: str | None
    status: str
    confidence: str  # "high" | "medium" | "low"
    providers: list[str]
    provider_evidence: list[ProviderEvidence]
    provider_reason: str | None  # surfaced for single-provider unknown/blocked findings

    def to_dict(self) -> dict:
        return {
            "platform": self.platform,
            "category": self.category,
            "profile_url": self.profile_url,
            "status": self.status,
            "confidence": self.confidence,
            "providers": self.providers,
            "provider_evidence": [e.to_dict() for e in self.provider_evidence],
            "provider_reason": self.provider_reason,
        }


def _gravatar_as_rows(gravatar_result) -> list[dict]:
    """
    Adapts GravatarIntegration's own IntegrationResult (has_profile:
    bool, profile_url, ...) into the same row shape the presence
    checkers emit, so it can participate in normalization as one more
    provider rather than a special case.
    """

    if gravatar_result is None:
        return []

    if gravatar_result.status not in _CONTRIBUTING_ENGINE_STATUSES:
        return []

    data = gravatar_result.data or {}
    has_profile = data.get("has_profile")

    if has_profile is True:
        state = "confirmed"
    elif has_profile is False:
        state = "not_found"
    else:
        return []

    return [{
        "platform": "gravatar",
        "category": "identity",
        "status": state,
        "http_status": None,
        "profile_url": data.get("profile_url") or data.get("avatar_url"),
        "provider_reason": None,
    }]


def normalize_and_correlate(
    presence_result,
    gravatar_result=None,
) -> list[CanonicalFinding]:
    """
    Merges AccountPresenceIntegration's raw per-platform rows (and
    GravatarIntegration's result, if available) into one canonical
    finding per platform.
    """

    by_platform: dict[str, dict] = {}

    def _ingest(provider_name: str, rows: list[dict]) -> None:

        for row in rows:

            platform = row["platform"]
            entry = by_platform.setdefault(
                platform,
                {
                    "platform": platform,
                    "category": row.get("category"),
                    "profile_url": None,
                    "evidence": [],
                },
            )

            state = row.get("status", "unknown")

            if entry["profile_url"] is None and row.get("profile_url"):
                entry["profile_url"] = row.get("profile_url")

            entry["evidence"].append(
                ProviderEvidence(
                    provider=provider_name,
                    state=state,
                    http_status=row.get("http_status"),
                    profile_url=row.get("profile_url"),
                    provider_reason=row.get("provider_reason"),
                )
            )

    # account_presence is a single engine that always sweeps every
    # platform in one run - its per-row evidence is trustworthy
    # whenever the sweep produced structured results at all, even if
    # its own ModuleResultStatus isn't SUCCESS (e.g. a defensive FAILED
    # from an empty checks list). Gate on the presence of actual
    # results, not on engine-status membership - a real 15-for-15
    # UNKNOWN/BLOCKED sweep must still reach the frontend as 15
    # "Unable to Verify" findings, never silently dropped.
    if presence_result is not None:
        _ingest("account_presence", (presence_result.data or {}).get("results", []))

    _ingest("gravatar", _gravatar_as_rows(gravatar_result))

    findings: list[CanonicalFinding] = []

    for entry in by_platform.values():

        evidence: list[ProviderEvidence] = entry["evidence"]

        confirmed = [e for e in evidence if e.state in _CONFIRMED_STATES]
        not_found = [e for e in evidence if e.state in _NOT_FOUND_STATES]

        if confirmed and not_found:
            status = "conflict"
            confidence = "low"
            reason = None

        elif confirmed:
            status = "confirmed"
            confidence = "high" if len(confirmed) >= 2 else "medium"
            reason = None

        elif not_found:
            status = "not_found"
            confidence = "high" if len(not_found) >= 2 else "medium"
            reason = None

        else:
            status = "unknown"
            confidence = "low"
            # Surface the first specific reason (e.g. a BLOCKED
            # platform's honest justification) so "unable to verify"
            # never reads as an unexplained dead end in the UI.
            reason = next((e.provider_reason for e in evidence if e.provider_reason), None)

        findings.append(
            CanonicalFinding(
                platform=entry["platform"],
                category=entry["category"],
                profile_url=entry["profile_url"],
                status=status,
                confidence=confidence,
                providers=[e.provider for e in evidence],
                provider_evidence=evidence,
                provider_reason=reason,
            )
        )

    findings.sort(key=lambda f: f.platform.lower())

    return findings


def summarize_findings(findings: list[CanonicalFinding]) -> dict:
    """
    Aggregate counts for the Account & Social Presence summary line -
    confirmed accounts, confidently-absent platforms, and platforms we
    couldn't verify. Deliberately contains no score or level of any
    kind - see email_service.py docstring.
    """

    confirmed = [f for f in findings if f.status == "confirmed"]
    not_found = [f for f in findings if f.status == "not_found"]
    unable_to_verify = [f for f in findings if f.status in ("unknown", "conflict")]

    providers_seen: set[str] = set()
    for f in findings:
        providers_seen.update(f.providers)

    return {
        "confirmed_accounts": [f.to_dict() for f in confirmed],
        "not_found_platforms": [f.to_dict() for f in not_found],
        "unable_to_verify_platforms": [f.to_dict() for f in unable_to_verify],
        "platforms_evaluated": len(findings),
        "providers_consulted": sorted(providers_seen),
    }
