"""
Cross-engine normalization for Username Intelligence.

Sherlock/Maigret/WhatsMyName each return their own raw per-platform
rows (see base_checker.PlatformCheckResult / *_integration.py). This
module merges those raw rows into one canonical, deduplicated finding
per platform, with full provenance - this is deliberately the ONLY
place that interprets "what does it mean when engines agree/disagree
about a platform", so that logic isn't duplicated (and doesn't drift)
between the service layer and the frontend.

Nothing here computes or contributes to risk_score/risk_level -
Username Intelligence is profile-discovery, not threat scoring (see
UsernameIntelligenceService docstring).
"""

from dataclasses import dataclass
from dataclasses import field

from backend.app.models.investigation import ModuleResultStatus

# Only these two engine-level statuses mean "this engine actually
# executed and its per-platform rows are trustworthy evidence". An
# engine that was SKIPPED (not configured) or FAILED (e.g. invalid
# username, or every platform came back inconclusive) contributes NO
# platform rows to normalization - its data must never be silently
# read as "checked" or reinterpreted as NOT_FOUND. Real Username
# engines don't currently emit RATE_LIMITED, but it is excluded here
# for the same reason: a rate-limited provider did not actually check
# anything.
_CONTRIBUTING_ENGINE_STATUSES = {
    ModuleResultStatus.SUCCESS,
    ModuleResultStatus.NOT_FOUND,
}


@dataclass
class ProviderEvidence:

    provider: str
    state: str  # "confirmed" | "not_found" | "unknown"
    http_status: int | None
    profile_url: str | None
    error: str | None

    def to_dict(self) -> dict:
        return {
            "provider": self.provider,
            "state": self.state,
            "http_status": self.http_status,
            "profile_url": self.profile_url,
            "error": self.error,
        }


@dataclass
class CanonicalFinding:
    """
    One deduplicated, cross-engine finding for a single platform.

    status:
        "confirmed"   - at least one engine confirmed, no engine
                        contradicted it.
        "not_found"   - at least one engine confirmed absence, no
                        engine confirmed presence.
        "conflict"    - engines disagree (one confirmed, another
                        confirmed absence) - never silently resolved
                        to either side.
        "unknown"     - every contributing engine that checked this
                        platform was inconclusive (blocked, network
                        error, ambiguous response).
    """

    platform: str
    category: str | None
    profile_url: str | None
    status: str
    confidence: str  # "high" | "medium" | "low"
    providers: list[str]
    provider_evidence: list[ProviderEvidence]

    def to_dict(self) -> dict:
        return {
            "platform": self.platform,
            "category": self.category,
            "profile_url": self.profile_url,
            "status": self.status,
            "confidence": self.confidence,
            "providers": self.providers,
            "provider_evidence": [e.to_dict() for e in self.provider_evidence],
        }


def _row_state(row: dict) -> str:
    """Same tri-state vocabulary as base_checker.platform_check_state,
    applied to a serialized (already-dict) platform row."""

    if row.get("error") is not None:
        return "unknown"

    exists = row.get("exists")

    if exists is True:
        return "confirmed"

    if exists is False:
        return "not_found"

    return "unknown"


def normalize_and_correlate(engine_results: list) -> list[CanonicalFinding]:
    """
    Merges raw per-engine platform rows into one canonical finding per
    platform. `engine_results` is the list of raw IntegrationResult
    objects returned by the Sherlock/Maigret/WhatsMyName engines
    (engine_result.data["results"] holds each engine's platform rows).
    """

    by_platform: dict[str, dict] = {}

    for engine_result in engine_results:

        if engine_result.status not in _CONTRIBUTING_ENGINE_STATUSES:
            # SKIPPED / FAILED / RATE_LIMITED - this engine did not
            # produce trustworthy per-platform evidence. Its raw
            # IntegrationResult is still persisted separately for
            # audit, but it contributes nothing here.
            continue

        rows = (engine_result.data or {}).get("results", [])

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

            state = _row_state(row)

            if entry["profile_url"] is None and row.get("profile_url"):
                entry["profile_url"] = row.get("profile_url")

            entry["evidence"].append(
                ProviderEvidence(
                    provider=engine_result.source,
                    state=state,
                    http_status=row.get("http_status"),
                    profile_url=row.get("profile_url"),
                    error=row.get("error"),
                )
            )

    findings: list[CanonicalFinding] = []

    for entry in by_platform.values():

        evidence: list[ProviderEvidence] = entry["evidence"]

        confirmed = [e for e in evidence if e.state == "confirmed"]
        not_found = [e for e in evidence if e.state == "not_found"]

        if confirmed and not_found:
            status = "conflict"
            confidence = "low"

        elif confirmed:
            status = "confirmed"
            confidence = "high" if len(confirmed) >= 2 else "medium"

        elif not_found:
            status = "not_found"
            confidence = "high" if len(not_found) >= 2 else "medium"

        else:
            status = "unknown"
            confidence = "low"

        findings.append(
            CanonicalFinding(
                platform=entry["platform"],
                category=entry["category"],
                profile_url=entry["profile_url"],
                status=status,
                confidence=confidence,
                providers=[e.provider for e in evidence],
                provider_evidence=evidence,
            )
        )

    findings.sort(key=lambda f: f.platform.lower())

    return findings


def summarize_findings(findings: list[CanonicalFinding]) -> dict:
    """
    Aggregate counts for the Username summary/UI - confirmed profiles,
    confidently-absent platforms, and platforms we couldn't verify.
    Deliberately contains no score or level of any kind.
    """

    confirmed = [f for f in findings if f.status == "confirmed"]
    not_found = [f for f in findings if f.status == "not_found"]
    unknown = [f for f in findings if f.status in ("unknown", "conflict")]

    providers_seen: set[str] = set()
    for f in findings:
        providers_seen.update(f.providers)

    return {
        "confirmed_profiles": [f.to_dict() for f in confirmed],
        "not_found_platforms": [f.to_dict() for f in not_found],
        "unable_to_verify_platforms": [f.to_dict() for f in unknown],
        "platforms_evaluated": len(findings),
        "providers_consulted": sorted(providers_seen),
    }
