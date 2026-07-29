import re

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
