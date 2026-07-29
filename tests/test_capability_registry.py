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
