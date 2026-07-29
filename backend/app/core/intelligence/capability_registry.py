"""
Capability registry (Section 4).

Deliberately thin: everything it needs already lives in
investigation_registry.py. This module exists so callers that only
care about "is X actually production-ready" don't need to know
anything about the investigation-type registry's other fields, and so
there is exactly one function (`capability_report()`) that a README/
release-audit script, a dashboard, and an API endpoint can all call to
get the same answer - eliminating "UI says supported, README says
production ready, endpoint actually fails" by construction, since all
three would be reading the same computed report.
"""

from dataclasses import dataclass

from backend.app.core.intelligence.investigation_registry import list_definitions


@dataclass(frozen=True)
class CapabilityStatus:

    identifier: str
    label: str
    category: str
    production_status: str
    implementation_state: str
    api_state: str
    ui_state: str
    provider_state: str
    is_production_ready: bool
    discrepancy_warnings: list[str]

    def to_dict(self) -> dict:

        return {
            "identifier": self.identifier,
            "label": self.label,
            "category": self.category,
            "production_status": self.production_status,
            "implementation_state": self.implementation_state,
            "api_state": self.api_state,
            "ui_state": self.ui_state,
            "provider_state": self.provider_state,
            "is_production_ready": self.is_production_ready,
            "discrepancy_warnings": self.discrepancy_warnings,
        }


def _detect_discrepancies(definition) -> list[str]:
    """
    Flags the exact anti-pattern the spec calls out: a maturity claim
    inconsistent with the underlying implementation/api/provider state.
    """

    warnings = []

    if definition.production_status == "production" and definition.api_state != "tested":
        warnings.append(
            f"production_status='production' but api_state='{definition.api_state}' (not tested)"
        )

    if definition.production_status == "production" and definition.implementation_state != "implemented":
        warnings.append(
            f"production_status='production' but implementation_state='{definition.implementation_state}'"
        )

    if definition.production_status == "production" and definition.provider_state == "none":
        warnings.append(
            "production_status='production' but provider_state='none' (no providers configured)"
        )

    return warnings


def capability_report() -> list[CapabilityStatus]:

    report = []

    for definition in list_definitions():

        warnings = _detect_discrepancies(definition)

        is_production_ready = (
            definition.production_status == "production"
            and definition.implementation_state == "implemented"
            and definition.api_state == "tested"
            and not warnings
        )

        report.append(
            CapabilityStatus(
                identifier=definition.identifier,
                label=definition.label,
                category=definition.category,
                production_status=definition.production_status,
                implementation_state=definition.implementation_state,
                api_state=definition.api_state,
                ui_state=definition.ui_state,
                provider_state=definition.provider_state,
                is_production_ready=is_production_ready,
                discrepancy_warnings=warnings,
            )
        )

    return report


def capability_report_as_json() -> list[dict]:
    return [c.to_dict() for c in capability_report()]
