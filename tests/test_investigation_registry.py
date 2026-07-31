import re

from backend.app.core.intelligence.investigation_registry import Availability
from backend.app.core.intelligence.investigation_registry import get_definition
from backend.app.core.intelligence.investigation_registry import INVESTIGATION_TYPE_REGISTRY
from backend.app.core.intelligence.investigation_registry import is_registered
from backend.app.core.intelligence.investigation_registry import registry_as_json_export


def _real_investigation_type_values() -> set[str]:
    """
    Extracts the actual InvestigationType enum values directly from the
    model source file (not by importing it - the model imports
    SQLAlchemy, which this test suite must not require for this file to
    be collectible in every environment) - so this test fails loudly if
    the registry and the real enum ever drift apart.
    """

    text = open("backend/app/models/investigation.py", encoding="utf-8").read()
    match = re.search(r"class InvestigationType\(str, Enum\):(.*?)\n\nclass", text, re.DOTALL)
    return set(re.findall(r'^\s*\w+\s*=\s*"([^"]+)"', match.group(1), re.MULTILINE))


def test_registry_matches_real_enum_exactly():

    assert set(INVESTIGATION_TYPE_REGISTRY.keys()) == _real_investigation_type_values()


def test_get_definition_known_and_unknown():

    assert get_definition("file").label == "File Intelligence"
    assert get_definition("does_not_exist") is None


def test_is_registered():

    assert is_registered("username") is True
    assert is_registered("nonexistent") is False


def test_json_export_shape():

    export = registry_as_json_export()

    assert len(export) == len(INVESTIGATION_TYPE_REGISTRY)
    assert all("identifier" in d and "production_status" in d for d in export)


def test_every_definition_has_a_non_empty_label_and_description():

    for definition in INVESTIGATION_TYPE_REGISTRY.values():

        assert definition.label
        assert definition.description
        assert definition.identifier == definition.identifier.lower()


# ==========================================================
# Phase 1B: authoritative registry / capability contract
# ==========================================================

def test_no_duplicate_identifiers():
    """
    Dict keys can't literally duplicate, but a copy-paste error could
    still set identifier='x' on an entry stored under a different dict
    key - catch that mismatch explicitly.
    """

    for key, definition in INVESTIGATION_TYPE_REGISTRY.items():
        assert definition.identifier == key, (key, definition.identifier)


def test_every_definition_has_non_empty_required_metadata():
    """Malformed-required-metadata detection, per Phase 1B section 4."""

    valid_input_modes = {"text", "file", "image", "composite"}

    for definition in INVESTIGATION_TYPE_REGISTRY.values():

        assert definition.icon, definition.identifier
        assert definition.input_type, definition.identifier
        assert definition.validation_hint, definition.identifier
        assert definition.category, definition.identifier
        assert definition.input_mode in valid_input_modes, (definition.identifier, definition.input_mode)


def test_metadata_is_honestly_represented_as_not_yet_implemented():
    """
    Regression test for the Phase 1B audit finding: 'metadata' previously
    claimed implementation_state='partial', which implies some backend
    workflow exists. It doesn't - no service, no endpoint, no router
    registration (confirmed against the real router.py source in
    test_registry_router_reality.py). This must read as genuinely
    unavailable, not partially working.
    """

    metadata = get_definition("metadata")

    assert metadata.implementation_state == "planned"
    assert metadata.router_prefix is None
    assert metadata.availability == Availability.COMING_SOON
    assert metadata.unavailable_reason is not None


def test_available_type_has_no_unavailable_reason():

    username = get_definition("username")

    assert username.availability == Availability.AVAILABLE
    assert username.unavailable_reason is None


def test_experimental_type_is_still_usable_and_has_no_reason():
    """EXPERIMENTAL means 'usable, but expect rough edges' - not the same as unavailable."""

    reverse_image = get_definition("reverse_image")

    assert reverse_image.availability == Availability.EXPERIMENTAL
    assert reverse_image.unavailable_reason is None


def test_file_and_reverse_image_are_distinguishable_by_input_mode():
    """Both accept an upload, but must not collapse into the same input_mode."""

    assert get_definition("file").input_mode == "file"
    assert get_definition("reverse_image").input_mode == "image"


def test_composite_risk_assessment_distinguishable_from_text_input():

    risk_assessment = get_definition("risk_assessment")

    assert risk_assessment.input_mode == "composite"
    assert risk_assessment.input_mode not in ("text", "file", "image")


def test_to_dict_includes_availability_contract_fields():

    d = get_definition("username").to_dict()

    assert "availability" in d
    assert "unavailable_reason" in d
    assert "input_mode" in d
    assert "router_prefix" in d
    assert d["availability"] == "available"
