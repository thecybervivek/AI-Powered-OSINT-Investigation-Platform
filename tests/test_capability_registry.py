from backend.app.core.intelligence.capability_registry import capability_report
from backend.app.core.intelligence.capability_registry import capability_report_as_json
from backend.app.core.intelligence.investigation_registry import INVESTIGATION_TYPE_REGISTRY


def test_report_covers_every_registered_type():

    report = capability_report()

    assert len(report) == len(INVESTIGATION_TYPE_REGISTRY)


def test_production_and_tested_type_is_production_ready_with_no_warnings():

    by_id = {c.identifier: c for c in capability_report()}

    assert by_id["username"].is_production_ready is True
    assert by_id["username"].discrepancy_warnings == []


def test_experimental_type_is_not_flagged_as_production_ready_and_has_no_false_positive_warnings():

    by_id = {c.identifier: c for c in capability_report()}

    assert by_id["risk_assessment"].is_production_ready is False
    assert by_id["risk_assessment"].discrepancy_warnings == []


def test_partial_implementation_is_not_production_ready():

    by_id = {c.identifier: c for c in capability_report()}

    assert by_id["metadata"].is_production_ready is False


def test_json_export_shape():

    export = capability_report_as_json()

    assert len(export) == len(INVESTIGATION_TYPE_REGISTRY)
    assert all("is_production_ready" in c for c in export)


# ==========================================================
# Phase 1B: availability contract surfaced through /capabilities
# ==========================================================

def test_metadata_reports_coming_soon_not_falsely_available():

    by_id = {c.identifier: c for c in capability_report()}

    assert by_id["metadata"].availability == "coming_soon"
    assert by_id["metadata"].unavailable_reason is not None
    assert by_id["metadata"].discrepancy_warnings == []  # experimental status, not a discrepancy


def test_username_reports_available_with_no_reason():

    by_id = {c.identifier: c for c in capability_report()}

    assert by_id["username"].availability == "available"
    assert by_id["username"].unavailable_reason is None


def test_file_and_reverse_image_input_mode_distinguishable_via_capability_report():

    by_id = {c.identifier: c for c in capability_report()}

    assert by_id["file"].input_mode == "file"
    assert by_id["reverse_image"].input_mode == "image"


def test_no_sensitive_fields_present_in_capability_output():
    """
    The capability contract must never leak provider API keys, secrets,
    or internal config - a coarse but meaningful guard: none of the
    known sensitive substrings should appear anywhere in the exported
    JSON values.
    """

    export = capability_report_as_json()
    serialized = str(export).lower()

    for forbidden in ("api_key", "apikey", "secret", "password", "token", "/home/", "/mnt/", "c:\\\\"):
        assert forbidden not in serialized, forbidden


def test_router_mount_discrepancy_check_fires_for_unmounted_production_claim():
    """
    Generalizes the exact bug the Phase 1B audit found in 'metadata':
    claiming production/beta maturity with no actual mounted route.
    """

    from backend.app.core.intelligence.capability_registry import _detect_discrepancies
    from backend.app.core.intelligence.investigation_registry import InvestigationTypeDefinition

    fake = InvestigationTypeDefinition(
        identifier="fake", label="Fake", category="test", description="d", icon="i",
        input_type="text", validation_hint="h", router_prefix=None,
        implementation_state="implemented", api_state="tested", production_status="production",
    )

    warnings = _detect_discrepancies(fake)

    assert any("router_prefix is None" in w for w in warnings)


def test_deterministic_ordering_across_calls():
    """The capability list's order must be stable across repeated calls (dict insertion order)."""

    order_a = [c.identifier for c in capability_report()]
    order_b = [c.identifier for c in capability_report()]

    assert order_a == order_b
