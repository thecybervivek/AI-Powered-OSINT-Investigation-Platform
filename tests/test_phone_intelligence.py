import asyncio

import pytest

from backend.app.integrations.base import IntegrationResult
from backend.app.integrations.phone.numverify_integration import NumVerifyIntegration
from backend.app.integrations.phone.phone_validation_integration import PhoneValidationIntegration
from backend.app.models.investigation import ModuleResultStatus
from backend.app.schemas.phone import PhoneInvestigationRequest
from backend.app.services.phone_service import PhoneIntelligenceService

# This is the canonical example U.S. number used throughout Google's own
# libphonenumber documentation/tests - guaranteed structurally valid,
# stable, and not tied to any real subscriber.
VALID_US_NUMBER = "+14155552671"


def _service() -> PhoneIntelligenceService:
    # _compute_risk_score/_overall_status/_build_summary touch no
    # database state, so a None db is safe here - same pattern already
    # used by tests/test_file_intelligence_part3.py for FileIntelligenceService.
    return PhoneIntelligenceService(db=None)


# ==========================================================
# PhoneValidationIntegration (offline)
# ==========================================================

def test_phone_validation_accepts_valid_e164_number():

    result = asyncio.run(PhoneValidationIntegration().run(VALID_US_NUMBER))

    assert result.status == ModuleResultStatus.SUCCESS
    assert result.data["is_valid"] is True
    assert result.data["e164_format"] == VALID_US_NUMBER
    assert result.data["country_code"] == "US"
    assert result.data["country_calling_code"] == 1
    assert result.data["number_type"] != "unknown"


def test_phone_validation_rejects_unparseable_input():

    result = asyncio.run(PhoneValidationIntegration().run("12345"))

    assert result.status == ModuleResultStatus.NOT_FOUND
    assert result.data["is_valid"] is False
    assert result.data["is_possible"] is False
    assert "parse_error" in result.data


def test_phone_validation_flags_impossible_number_with_valid_prefix():

    # Has a leading "+" (parses) but is far too short to be a real
    # NANP subscriber number - is_valid_number/is_possible_number
    # should both report False.
    result = asyncio.run(PhoneValidationIntegration().run("+1415555"))

    assert result.status == ModuleResultStatus.NOT_FOUND
    assert result.data["is_valid"] is False


def test_phone_validation_is_always_configured():

    assert PhoneValidationIntegration().is_configured() is True


# ==========================================================
# NumVerifyIntegration (optional, key-gated)
# ==========================================================

def test_numverify_skips_gracefully_without_api_key():

    integration = NumVerifyIntegration()
    assert integration.is_configured() is False

    result = asyncio.run(integration.run(VALID_US_NUMBER))

    assert result.status == ModuleResultStatus.SKIPPED
    assert "not configured" in result.error_message.lower()


# ==========================================================
# PhoneInvestigationRequest schema
# ==========================================================

def test_phone_schema_accepts_well_formed_number():

    request = PhoneInvestigationRequest(phone_number=" +1 415-555-2671 ")
    assert request.phone_number == "+1 415-555-2671"


def test_phone_schema_rejects_disallowed_characters():

    with pytest.raises(ValueError):
        PhoneInvestigationRequest(phone_number="call me maybe 555")


# ==========================================================
# PhoneIntelligenceService risk scoring (pure logic, no DB)
# ==========================================================

def test_risk_score_zero_for_valid_non_voip_number():

    service = _service()

    results = {
        "phone_validation": IntegrationResult(
            source="phone_validation",
            status=ModuleResultStatus.SUCCESS,
            data={"is_valid": True, "number_type": "mobile"},
        ),
    }

    score, notes = service._compute_risk_score(results)

    assert score == 0.0
    assert notes == []


def test_risk_score_increases_for_invalid_number():

    service = _service()

    results = {
        "phone_validation": IntegrationResult(
            source="phone_validation",
            status=ModuleResultStatus.NOT_FOUND,
            data={"is_valid": False, "number_type": "unknown"},
        ),
    }

    score, notes = service._compute_risk_score(results)

    assert score > 0
    assert any("does not validate" in note for note in notes)


def test_risk_score_flags_voip_number_type():

    service = _service()

    results = {
        "phone_validation": IntegrationResult(
            source="phone_validation",
            status=ModuleResultStatus.SUCCESS,
            data={"is_valid": True, "number_type": "voip"},
        ),
    }

    score, notes = service._compute_risk_score(results)

    assert score > 0
    assert any("voip" in note.lower() for note in notes)


def test_risk_score_combines_numverify_voip_confirmation():

    service = _service()

    results = {
        "phone_validation": IntegrationResult(
            source="phone_validation",
            status=ModuleResultStatus.SUCCESS,
            data={"is_valid": True, "number_type": "mobile"},
        ),
        "numverify": IntegrationResult(
            source="numverify",
            status=ModuleResultStatus.SUCCESS,
            data={"line_type": "voip"},
        ),
    }

    score, notes = service._compute_risk_score(results)

    assert score > 0
    assert any("numverify" in note.lower() for note in notes)


def test_overall_status_completed_when_only_optional_source_skipped():

    service = _service()

    engine_results = [
        IntegrationResult(source="phone_validation", status=ModuleResultStatus.SUCCESS, data={}),
        IntegrationResult(source="numverify", status=ModuleResultStatus.SKIPPED, data={}),
    ]

    assert service._overall_status(engine_results).value == "completed"


def test_build_summary_reports_invalid_number_distinctly():

    service = _service()

    results = {
        "phone_validation": IntegrationResult(
            source="phone_validation",
            status=ModuleResultStatus.NOT_FOUND,
            data={"is_valid": False},
        ),
    }

    summary = service._build_summary("+1415555", results, [])

    assert "does not validate" in summary
