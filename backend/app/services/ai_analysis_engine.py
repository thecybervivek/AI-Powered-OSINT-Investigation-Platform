import json
import logging
from dataclasses import dataclass
from dataclasses import field
from typing import Any

import httpx

from backend.app.core.config import settings
from backend.app.models.investigation import Investigation
from backend.app.models.investigation import ModuleResultStatus
from backend.app.models.investigation import RiskLevel
from backend.app.models.report import AIEngineUsed
from backend.app.utils.http_client import request_with_retry
from backend.app.utils.risk_scoring import clamp
from backend.app.utils.privacy import redact_for_external_ai

logger = logging.getLogger("app.services.ai_analysis_engine")

_RISK_ORDER = {
    RiskLevel.LOW: 0,
    RiskLevel.MEDIUM: 1,
    RiskLevel.HIGH: 2,
    RiskLevel.CRITICAL: 3,
}


@dataclass
class AIAnalysisResult:

    executive_summary: str
    technical_analysis: str
    threat_summary: str
    confidence_score: float
    evidence_correlation: list[dict[str, Any]] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)
    risk_explanation: str = ""
    engine_used: AIEngineUsed = AIEngineUsed.LOCAL_DETERMINISTIC


def flatten_evidence(
    investigations: list[Investigation],
) -> list[dict[str, Any]]:
    """
    Turns every fetched Investigation + its InvestigationResult rows into
    a flat list of evidence dicts - the shared shape both the MITRE
    mapper and the AI analyzer (either engine) work from.
    """

    evidence: list[dict[str, Any]] = []

    for investigation in investigations:

        for result in investigation.results:

            evidence.append(
                {
                    "investigation_id": investigation.id,
                    "investigation_type": investigation.investigation_type.value,
                    "investigation_target": investigation.target,
                    "source": result.source,
                    "status": result.status.value,
                    "data": result.data,
                }
            )

    return evidence


class AIAnalysisEngine:
    """
    Consumes results from every intelligence module (Username, Email,
    Domain, IP, URL, IOC, File) for a set of investigations and produces
    a correlated analysis: executive summary, technical detail, threat
    summary, confidence score, cross-investigation correlation,
    recommendations, and a plain-language risk explanation.

    Uses OpenAI when OPENAI_API_KEY is configured; on ANY failure
    (missing key, network error, malformed response) it falls back to
    the deterministic local analyzer below. Report generation must never
    fail purely because the optional AI provider is unavailable.
    """

    async def analyze(
        self,
        investigations: list[Investigation],
    ) -> AIAnalysisResult:

        evidence_items = flatten_evidence(investigations)

        if settings.EXTERNAL_AI_PROCESSING_ENABLED and settings.OPENAI_API_KEY:

            try:
                return await self._analyze_with_openai(investigations, evidence_items)

            except Exception as error:

                logger.warning(
                    "OpenAI analysis failed; falling back to the deterministic "
                    "local analyzer: %s",
                    error,
                )

        return self._analyze_locally(investigations, evidence_items)

    # ==========================================================
    # OpenAI-backed analysis
    # ==========================================================

    async def _analyze_with_openai(
        self,
        investigations: list[Investigation],
        evidence_items: list[dict[str, Any]],
    ) -> AIAnalysisResult:

        # Evidence payloads can be large; cap what's sent to the model to
        # keep prompts bounded and avoid leaking oversized raw responses.
        trimmed_evidence = [
            {
                "investigation_type": e["investigation_type"],
                "investigation_target": e["investigation_target"],
                "source": e["source"],
                "status": e["status"],
                "data": e["data"],
            }
            for e in evidence_items
][:200]

        if settings.AI_REDACT_SENSITIVE_DATA:
            trimmed_evidence = redact_for_external_ai(trimmed_evidence)

        system_prompt = (
            "You are a senior cybersecurity threat analyst. You are given "
            "structured OSINT investigation evidence as JSON. Respond with "
            "ONLY a single JSON object (no markdown fences, no commentary) "
            "with exactly these keys: executive_summary (string), "
            "technical_analysis (string), threat_summary (string), "
            "confidence_score (number 0-100), evidence_correlation "
            "(array of objects with 'finding' and 'related_sources'), "
            "recommendations (array of strings), risk_explanation (string)."
        )

        user_prompt = json.dumps(
            {
                "investigation_count": len(investigations),
                "investigation_types": sorted(
                    {i.investigation_type.value for i in investigations}
                ),
                "evidence": trimmed_evidence,
            },
            default=str,
        )

        payload = {
            "model": settings.OPENAI_MODEL,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": 0.2,
            "response_format": {"type": "json_object"},
        }

        headers = {
            "Authorization": f"Bearer {settings.OPENAI_API_KEY}",
            "Content-Type": "application/json",
        }

        async with httpx.AsyncClient(
            timeout=settings.OPENAI_REQUEST_TIMEOUT_SECONDS,
        ) as client:

            response = await request_with_retry(
                client,
                "POST",
                f"{settings.OPENAI_BASE_URL}/chat/completions",
                headers=headers,
                json=payload,
                max_retries=1,
            )

        if response.status_code != 200:
            raise RuntimeError(f"External AI provider returned HTTP {response.status_code}.")

        completion = response.json()
        content = completion["choices"][0]["message"]["content"]
        parsed = json.loads(content)

        return AIAnalysisResult(
            executive_summary=str(parsed["executive_summary"]),
            technical_analysis=str(parsed["technical_analysis"]),
            threat_summary=str(parsed["threat_summary"]),
            confidence_score=clamp(float(parsed.get("confidence_score", 50))),
            evidence_correlation=list(parsed.get("evidence_correlation", [])),
            recommendations=[str(r) for r in parsed.get("recommendations", [])],
            risk_explanation=str(parsed.get("risk_explanation", "")),
            engine_used=AIEngineUsed.OPENAI,
        )

    # ==========================================================
    # Deterministic local analysis (always available, never fails)
    # ==========================================================

    def _analyze_locally(
        self,
        investigations: list[Investigation],
        evidence_items: list[dict[str, Any]],
    ) -> AIAnalysisResult:

        type_counts: dict[str, int] = {}

        for inv in investigations:
            type_counts[inv.investigation_type.value] = (
                type_counts.get(inv.investigation_type.value, 0) + 1
            )

        risk_scored = [inv for inv in investigations if inv.risk_score is not None]
        highest_risk_investigation = (
            max(risk_scored, key=lambda i: i.risk_score) if risk_scored else None
        )

        actionable = [e for e in evidence_items if e["status"] != ModuleResultStatus.SKIPPED.value]
        successful = [e for e in actionable if e["status"] == ModuleResultStatus.SUCCESS.value]

        confidence_score = clamp(
            (len(successful) / len(actionable) * 100) if actionable else 0.0
        )

        executive_summary = self._build_executive_summary(
            investigations, type_counts, highest_risk_investigation
        )
        technical_analysis = self._build_technical_analysis(investigations)
        threat_summary = self._build_threat_summary(investigations)
        evidence_correlation = self._build_evidence_correlation(investigations)
        recommendations = self._build_recommendations(investigations, evidence_items)
        risk_explanation = self._build_risk_explanation(
            investigations, highest_risk_investigation
        )

        return AIAnalysisResult(
            executive_summary=executive_summary,
            technical_analysis=technical_analysis,
            threat_summary=threat_summary,
            confidence_score=confidence_score,
            evidence_correlation=evidence_correlation,
            recommendations=recommendations,
            risk_explanation=risk_explanation,
            engine_used=AIEngineUsed.LOCAL_DETERMINISTIC,
        )

    @staticmethod
    def _build_executive_summary(
        investigations: list[Investigation],
        type_counts: dict[str, int],
        highest_risk_investigation: Investigation | None,
    ) -> str:

        type_breakdown = ", ".join(
            f"{count} {itype}" for itype, count in sorted(type_counts.items())
        )

        lines = [
            f"This report correlates {len(investigations)} investigation(s) "
            f"({type_breakdown})."
        ]

        if highest_risk_investigation and highest_risk_investigation.risk_level:

            lines.append(
                f"The highest-risk finding is '{highest_risk_investigation.target}' "
                f"({highest_risk_investigation.investigation_type.value}), assessed at "
                f"{highest_risk_investigation.risk_level.value.upper()} risk "
                f"(score {highest_risk_investigation.risk_score:.1f}/100)."
            )

        else:
            lines.append("No investigation in this report reached an elevated risk level.")

        return " ".join(lines)

    @staticmethod
    def _build_technical_analysis(investigations: list[Investigation]) -> str:
        """
        Reuses each module's own already-computed summary (every service
        in this platform - ip_service, domain_service, file_service, etc.
        - already builds a target-specific summary), rather than
        re-deriving technical detail the modules have already produced.
        """

        lines = []

        for inv in investigations:

            summary = inv.summary or "No summary available."
            lines.append(
                f"[{inv.investigation_type.value}] '{inv.target}': {summary}"
            )

        return "\n".join(lines)

    @staticmethod
    def _build_threat_summary(investigations: list[Investigation]) -> str:

        elevated = [
            inv
            for inv in investigations
            if inv.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL)
        ]

        if not elevated:
            return (
                "No investigation in this report was assessed as HIGH or "
                "CRITICAL risk. No immediate threat indicators identified."
            )

        parts = [
            f"'{inv.target}' ({inv.investigation_type.value}, "
            f"{inv.risk_level.value.upper()})"
            for inv in elevated
        ]

        return (
            f"{len(elevated)} of {len(investigations)} investigation(s) were "
            f"assessed as HIGH or CRITICAL risk: " + "; ".join(parts) + "."
        )

    @staticmethod
    def _build_evidence_correlation(
        investigations: list[Investigation],
    ) -> list[dict[str, Any]]:

        correlations: list[dict[str, Any]] = []

        elevated = [
            inv
            for inv in investigations
            if inv.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL)
        ]

        if len(elevated) >= 2:

            correlations.append(
                {
                    "finding": (
                        "Multiple independently-analyzed targets in this "
                        "report converge on elevated risk, suggesting a "
                        "single coordinated threat rather than isolated "
                        "unrelated findings."
                    ),
                    "related_sources": [
                        f"{inv.investigation_type.value}:{inv.target}"
                        for inv in elevated
                    ],
                }
            )

        targets_by_type = {
            inv.investigation_type.value: inv.target for inv in investigations
        }

        if "domain" in targets_by_type and "ip_address" in targets_by_type:

            correlations.append(
                {
                    "finding": (
                        f"Both a domain ('{targets_by_type['domain']}') and an "
                        f"IP address ('{targets_by_type['ip_address']}') were "
                        f"investigated together in this report; cross-check "
                        f"the domain's DNS resolution against the analyzed IP "
                        f"to confirm they represent the same infrastructure."
                    ),
                    "related_sources": ["domain", "ip_address"],
                }
            )

        return correlations

    @staticmethod
    def _build_recommendations(
        investigations: list[Investigation],
        evidence_items: list[dict[str, Any]],
    ) -> list[str]:

        recommendations: list[str] = []

        for inv in investigations:

            if inv.risk_level not in (RiskLevel.HIGH, RiskLevel.CRITICAL):
                continue

            if inv.investigation_type.value == "file":
                recommendations.append(
                    f"Quarantine the file '{inv.target}' and do not execute "
                    f"it; verify it hasn't already run on any endpoint."
                )

            elif inv.investigation_type.value == "ip_address":
                recommendations.append(
                    f"Block '{inv.target}' at the network perimeter (firewall/"
                    f"proxy) and review logs for prior connections to it."
                )

            elif inv.investigation_type.value == "domain":
                recommendations.append(
                    f"Block/sinkhole '{inv.target}' at the DNS or web proxy "
                    f"layer and review logs for prior resolutions of it."
                )

            elif inv.investigation_type.value == "url":
                recommendations.append(
                    f"Block access to '{inv.target}' and warn any users who "
                    f"may have received it, particularly via email."
                )

            elif inv.investigation_type.value == "email":
                recommendations.append(
                    f"Force a password reset for any account associated with "
                    f"'{inv.target}' and enable MFA if not already active."
                )

            else:
                recommendations.append(
                    f"Review '{inv.target}' ({inv.investigation_type.value}) "
                    f"further given its {inv.risk_level.value.upper()} risk "
                    f"assessment."
                )

        if not recommendations:
            recommendations.append(
                "No elevated-risk findings in this report; continue routine "
                "monitoring."
            )

        return recommendations

    @staticmethod
    def _build_risk_explanation(
        investigations: list[Investigation],
        highest_risk_investigation: Investigation | None,
    ) -> str:

        if highest_risk_investigation is None or not highest_risk_investigation.risk_score:
            return (
                "No investigation in this report produced a meaningful risk "
                "score; the overall risk assessment reflects a lack of "
                "elevated findings, not a confirmed-safe verdict."
            )

        return (
            f"The overall risk score is driven primarily by "
            f"'{highest_risk_investigation.target}' "
            f"({highest_risk_investigation.investigation_type.value}), which "
            f"individually scored {highest_risk_investigation.risk_score:.1f}/100. "
            f"{highest_risk_investigation.summary or ''}"
        ).strip()
