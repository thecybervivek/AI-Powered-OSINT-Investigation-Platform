import asyncio

import pytest

from backend.app.integrations.base import IntegrationResult
from backend.app.integrations.phone.numverify_integration import NumVerifyIntegration
from backend.app.integrations.phone.phone_breach_integration import PhoneBreachIntegration
from backend.app.integrations.phone.phone_public_intelligence_integration import (
    PhonePublicIntelligenceIntegration,
)
from backend.app.integrations.phone.phone_reputation_integration import PhoneReputationIntegration
from backend.app.integrations.phone.phone_validation_integration import PhoneValidationIntegration
from backend.app.models.investigation import ModuleResultStatus
from backend.app.schemas.phone import PhoneInvestigationRequest
from backend.app.services.phone_service import PhoneIntelligenceService

# This is the canonical example U.S. number used throughout Google's own
# libphonenumber documentation/tests - guaranteed structurally valid,
# stable, and not tied to any real subscriber.
VALID_US_NUMBER = "+14155552671"

# The exact number from the reported regression: a valid Indian mobile
# number typed without the "+91" country code.
INDIAN_NUMBER_NO_PREFIX = "9917891298"
INDIAN_NUMBER_E164 = "+919917891298"


def _service() -> PhoneIntelligenceService:
    # _compute_risk_score/_overall_status/_build_summary/_build_overview
    # touch no database state, so a None db is safe here - same pattern
    # already used by tests/test_file_intelligence_part3.py for
    # FileIntelligenceService.
    return PhoneIntelligenceService(db=None)


# ==========================================================
# PhoneValidationIntegration (offline) - regression coverage
# ==========================================================

def test_phone_validation_accepts_valid_e164_number():

    result = asyncio.run(PhoneValidationIntegration().run(VALID_US_NUMBER))

    assert result.status == ModuleResultStatus.SUCCESS
    assert result.data["is_valid"] is True
    assert result.data["e164_format"] == VALID_US_NUMBER
    assert result.data["country_code"] == "US"
    assert result.data["country_calling_code"] == 1
    assert result.data["number_type"] != "unknown"
    assert result.data["assumed_country"] is None


def test_phone_validation_normalizes_indian_number_without_prefix():
    """
    Regression test (permanent fix): 9917891298 must resolve to a
    SUCCESS/valid Indian mobile number, normalized to +919917891298 -
    not NOT_FOUND/invalid the way it did before the India fallback
    region was added to PhoneValidationIntegration._parse().
    """

    result = asyncio.run(PhoneValidationIntegration().run(INDIAN_NUMBER_NO_PREFIX))

    assert result.status == ModuleResultStatus.SUCCESS
    assert result.data["is_valid"] is True
    assert result.data["e164_format"] == INDIAN_NUMBER_E164
    assert result.data["country_code"] == "IN"
    assert result.data["assumed_country"] == "IN"


def test_phone_validation_e164_indian_number_remains_valid():

    result = asyncio.run(PhoneValidationIntegration().run(INDIAN_NUMBER_E164))

    assert result.status == ModuleResultStatus.SUCCESS
    assert result.data["is_valid"] is True
    assert result.data["e164_format"] == INDIAN_NUMBER_E164
    # Already carried its own "+91" - no fallback region was needed.
    assert result.data["assumed_country"] is None


def test_phone_validation_rejects_unparseable_input():

    result = asyncio.run(PhoneValidationIntegration().run("random text"))

    assert result.status == ModuleResultStatus.NOT_FOUND
    assert result.data["is_valid"] is False
    assert result.data["is_possible"] is False
    assert "parse_error" in result.data


def test_phone_validation_fails_safely_on_malformed_international_number():

    # Has a leading "+" (parses) but is far too short to be a real
    # NANP subscriber number - is_valid_number/is_possible_number
    # should both report False, with no fallback-region retry (it
    # already carries a "+").
    result = asyncio.run(PhoneValidationIntegration().run("+1415555"))

    assert result.status == ModuleResultStatus.NOT_FOUND
    assert result.data["is_valid"] is False


def test_phone_validation_is_always_configured():

    assert PhoneValidationIntegration().is_configured() is True


# ==========================================================
# Optional providers - all SKIPPED gracefully without configuration
# ==========================================================

def test_numverify_skips_gracefully_without_api_key():

    integration = NumVerifyIntegration()
    assert integration.is_configured() is False

    result = asyncio.run(integration.run(VALID_US_NUMBER))

    assert result.status == ModuleResultStatus.SKIPPED
    assert "not configured" in result.error_message.lower()


def test_phone_reputation_skips_gracefully_without_api_key():

    integration = PhoneReputationIntegration()
    assert integration.is_configured() is False

    result = asyncio.run(integration.run(VALID_US_NUMBER))

    assert result.status == ModuleResultStatus.SKIPPED


def test_phone_breach_skips_gracefully_without_api_key():

    integration = PhoneBreachIntegration()
    assert integration.is_configured() is False

    result = asyncio.run(integration.run(VALID_US_NUMBER))

    assert result.status == ModuleResultStatus.SKIPPED


def test_phone_public_intelligence_skips_gracefully_without_api_key():

    integration = PhonePublicIntelligenceIntegration()
    assert integration.is_configured() is False

    result = asyncio.run(integration.run(VALID_US_NUMBER))

    assert result.status == ModuleResultStatus.SKIPPED


# ==========================================================
# PhoneInvestigationRequest schema
# ==========================================================

def test_phone_schema_accepts_well_formed_number():

    request = PhoneInvestigationRequest(phone_number=" +1 415-555-2671 ")
    assert request.phone_number == "+1 415-555-2671"


def test_phone_schema_accepts_indian_number_without_prefix():

    request = PhoneInvestigationRequest(phone_number=INDIAN_NUMBER_NO_PREFIX)
    assert request.phone_number == INDIAN_NUMBER_NO_PREFIX


def test_phone_schema_rejects_disallowed_characters():

    with pytest.raises(ValueError):
        PhoneInvestigationRequest(phone_number="call me maybe 555")


# ==========================================================
# PhoneIntelligenceService risk scoring - evidence-driven only
# (spec section 10/11 + section 17 regression suite)
# ==========================================================

def test_risk_score_zero_for_valid_number_no_findings():

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


def test_risk_score_stays_zero_for_indian_number_missing_country_code():
    """
    The exact regression case: a validation result for a number that
    only resolved via the India fallback region must NOT be treated as
    risk-worthy on its own.
    """

    service = _service()

    results = {
        "phone_validation": IntegrationResult(
            source="phone_validation",
            status=ModuleResultStatus.SUCCESS,
            data={
                "is_valid": True,
                "number_type": "mobile",
                "assumed_country": "IN",
            },
        ),
    }

    score, notes = service._compute_risk_score(results)

    assert score == 0.0
    assert notes == []


def test_risk_score_not_increased_by_invalid_validation():

    service = _service()

    results = {
        "phone_validation": IntegrationResult(
            source="phone_validation",
            status=ModuleResultStatus.NOT_FOUND,
            data={"is_valid": False, "number_type": "unknown"},
        ),
    }

    score, notes = service._compute_risk_score(results)

    assert score == 0.0
    assert notes == []


def test_risk_score_not_increased_by_failed_validation():

    service = _service()

    results = {
        "phone_validation": IntegrationResult(
            source="phone_validation",
            status=ModuleResultStatus.FAILED,
            data=None,
        ),
    }

    score, notes = service._compute_risk_score(results)

    assert score == 0.0
    assert notes == []


def test_risk_score_not_increased_by_unknown_validation():

    service = _service()

    results = {
        "phone_validation": IntegrationResult(
            source="phone_validation",
            status=ModuleResultStatus.RATE_LIMITED,
            data=None,
        ),
    }

    score, notes = service._compute_risk_score(results)

    assert score == 0.0
    assert notes == []


def test_risk_score_not_increased_by_skipped_provider():

    service = _service()

    results = {
        "numverify": IntegrationResult(
            source="numverify", status=ModuleResultStatus.SKIPPED, data=None,
        ),
        "phone_reputation": IntegrationResult(
            source="phone_reputation", status=ModuleResultStatus.SKIPPED, data=None,
        ),
        "phone_breach": IntegrationResult(
            source="phone_breach", status=ModuleResultStatus.SKIPPED, data=None,
        ),
    }

    score, notes = service._compute_risk_score(results)

    assert score == 0.0
    assert notes == []


def test_risk_score_not_increased_by_rate_limited_provider():

    service = _service()

    results = {
        "phone_breach": IntegrationResult(
            source="phone_breach", status=ModuleResultStatus.RATE_LIMITED, data=None,
        ),
    }

    score, notes = service._compute_risk_score(results)

    assert score == 0.0
    assert notes == []


def test_risk_score_not_increased_by_carrier_or_line_type_metadata():

    service = _service()

    results = {
        "phone_validation": IntegrationResult(
            source="phone_validation",
            status=ModuleResultStatus.SUCCESS,
            data={"is_valid": True, "number_type": "voip"},
        ),
        "numverify": IntegrationResult(
            source="numverify",
            status=ModuleResultStatus.SUCCESS,
            data={"line_type": "voip", "carrier": "Some Carrier"},
        ),
    }

    score, notes = service._compute_risk_score(results)

    assert score == 0.0
    assert notes == []


def test_risk_score_not_increased_by_public_profile_presence():

    service = _service()

    results = {
        "phone_public_intelligence": IntegrationResult(
            source="phone_public_intelligence",
            status=ModuleResultStatus.SUCCESS,
            data={"public_references": [{"url": "https://example.com/listing"}]},
        ),
    }

    score, notes = service._compute_risk_score(results)

    assert score == 0.0
    assert notes == []


def test_risk_score_increases_for_confirmed_breach():

    service = _service()

    results = {
        "phone_breach": IntegrationResult(
            source="phone_breach",
            status=ModuleResultStatus.SUCCESS,
            data={"total_entries": 2, "has_plaintext_password_exposure": False},
        ),
    }

    score, notes = service._compute_risk_score(results)

    assert score > 0
    assert any("breach" in note.lower() for note in notes)


def test_risk_score_increases_more_for_plaintext_password_breach():

    service = _service()

    results = {
        "phone_breach": IntegrationResult(
            source="phone_breach",
            status=ModuleResultStatus.SUCCESS,
            data={"total_entries": 1, "has_plaintext_password_exposure": True},
        ),
    }

    score, notes = service._compute_risk_score(results)

    assert score > 10
    assert any("plaintext" in note.lower() for note in notes)


def test_risk_score_not_increased_by_breach_not_found():

    service = _service()

    results = {
        "phone_breach": IntegrationResult(
            source="phone_breach",
            status=ModuleResultStatus.NOT_FOUND,
            data={"total_entries": 0},
        ),
    }

    score, notes = service._compute_risk_score(results)

    assert score == 0.0
    assert notes == []


def test_risk_score_increases_for_confirmed_malicious_reputation():

    service = _service()

    results = {
        "phone_reputation": IntegrationResult(
            source="phone_reputation",
            status=ModuleResultStatus.SUCCESS,
            data={"malicious_activity": True},
        ),
    }

    score, notes = service._compute_risk_score(results)

    assert score > 0
    assert any("malicious" in note.lower() for note in notes)


def test_risk_score_not_increased_by_failed_reputation_provider():

    service = _service()

    results = {
        "phone_reputation": IntegrationResult(
            source="phone_reputation",
            status=ModuleResultStatus.FAILED,
            data=None,
        ),
    }

    score, notes = service._compute_risk_score(results)

    assert score == 0.0
    assert notes == []


# ==========================================================
# Overall status
# ==========================================================

def test_overall_status_completed_when_only_optional_sources_skipped():

    service = _service()

    engine_results = [
        IntegrationResult(source="phone_validation", status=ModuleResultStatus.SUCCESS, data={}),
        IntegrationResult(source="numverify", status=ModuleResultStatus.SKIPPED, data={}),
        IntegrationResult(source="phone_reputation", status=ModuleResultStatus.SKIPPED, data={}),
        IntegrationResult(source="phone_breach", status=ModuleResultStatus.SKIPPED, data={}),
        IntegrationResult(source="phone_public_intelligence", status=ModuleResultStatus.SKIPPED, data={}),
    ]

    assert service._overall_status(engine_results).value == "completed"


def test_overall_status_partial_when_a_provider_is_rate_limited():
    """
    Regression test: base.py previously collapsed IntegrationRateLimitError
    into a generic FAILED, so RATE_LIMITED never actually appeared here in
    practice and _overall_status's hand-written `== ModuleResultStatus.FAILED`
    check happened to be exercised by every non-conclusive case. Now that
    base.py returns RATE_LIMITED distinctly, _overall_status must still
    treat it as non-conclusive (not silently report COMPLETED).
    """

    service = _service()

    engine_results = [
        IntegrationResult(source="phone_validation", status=ModuleResultStatus.SUCCESS, data={}),
        IntegrationResult(source="numverify", status=ModuleResultStatus.RATE_LIMITED, data={}),
        IntegrationResult(source="phone_reputation", status=ModuleResultStatus.SKIPPED, data={}),
        IntegrationResult(source="phone_breach", status=ModuleResultStatus.SKIPPED, data={}),
        IntegrationResult(source="phone_public_intelligence", status=ModuleResultStatus.SKIPPED, data={}),
    ]

    assert service._overall_status(engine_results).value == "partial"


def test_overall_status_failed_when_every_actionable_provider_is_rate_limited():

    service = _service()

    engine_results = [
        IntegrationResult(source="phone_validation", status=ModuleResultStatus.RATE_LIMITED, data={}),
        IntegrationResult(source="numverify", status=ModuleResultStatus.SKIPPED, data={}),
    ]

    assert service._overall_status(engine_results).value == "failed"


# ==========================================================
# Summary text
# ==========================================================

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


def test_build_summary_reflects_partial_results_when_providers_unavailable():

    service = _service()

    results = {
        "phone_validation": IntegrationResult(
            source="phone_validation",
            status=ModuleResultStatus.SUCCESS,
            data={"is_valid": True},
        ),
        "numverify": IntegrationResult(
            source="numverify", status=ModuleResultStatus.SKIPPED, data=None,
        ),
        "phone_reputation": IntegrationResult(
            source="phone_reputation", status=ModuleResultStatus.SKIPPED, data=None,
        ),
        "phone_breach": IntegrationResult(
            source="phone_breach", status=ModuleResultStatus.SKIPPED, data=None,
        ),
        "phone_public_intelligence": IntegrationResult(
            source="phone_public_intelligence", status=ModuleResultStatus.SKIPPED, data=None,
        ),
    }

    summary = service._build_summary(INDIAN_NUMBER_NO_PREFIX, results, [])

    assert "unavailable" in summary
    assert "safe" not in summary.lower()


def test_build_summary_never_says_no_breaches_found_when_not_checked():

    service = _service()

    results = {
        "phone_validation": IntegrationResult(
            source="phone_validation",
            status=ModuleResultStatus.SUCCESS,
            data={"is_valid": True},
        ),
        "phone_breach": IntegrationResult(
            source="phone_breach", status=ModuleResultStatus.SKIPPED, data=None,
        ),
    }

    summary = service._build_summary(VALID_US_NUMBER, results, [])

    assert "no breaches found" not in summary.lower()


def test_build_summary_reports_confirmed_breach_findings():

    service = _service()

    results = {
        "phone_validation": IntegrationResult(
            source="phone_validation",
            status=ModuleResultStatus.SUCCESS,
            data={"is_valid": True},
        ),
    }

    summary = service._build_summary(
        VALID_US_NUMBER,
        results,
        ["confirmed breach exposure across 2 records"],
    )

    assert "breach exposure" in summary.lower()


# ==========================================================
# Phone Overview - normalization/dedup across providers
# ==========================================================

def test_build_overview_normalizes_indian_number_without_prefix():

    service = _service()

    results = {
        "phone_validation": IntegrationResult(
            source="phone_validation",
            status=ModuleResultStatus.SUCCESS,
            data={
                "raw_input": INDIAN_NUMBER_NO_PREFIX,
                "e164_format": INDIAN_NUMBER_E164,
                "is_valid": True,
                "is_possible": True,
                "region_description": "India",
                "country_calling_code": 91,
                "country_code": "IN",
                "number_type": "mobile",
                "international_format": "+91 99178 91298",
                "national_format": "099178 91298",
                "timezones": ["Asia/Calcutta"],
                "assumed_country": "IN",
            },
        ),
    }

    overview = service._build_overview(results)

    assert overview["normalized_e164"] == INDIAN_NUMBER_E164
    assert overview["is_valid"] is True
    assert overview["assumed_country"] == "IN"
    assert "phone_validation" in overview["providers_consulted"]


def test_build_overview_merges_duplicate_provider_representations():
    """
    Provider A (offline validation) and Provider B (NumVerify) both
    describing the same normalized number should collapse into one
    overview entity that lists both providers - not two conflicting
    rows (spec section 9).
    """

    service = _service()

    results = {
        "phone_validation": IntegrationResult(
            source="phone_validation",
            status=ModuleResultStatus.SUCCESS,
            data={
                "raw_input": INDIAN_NUMBER_NO_PREFIX,
                "e164_format": INDIAN_NUMBER_E164,
                "is_valid": True,
                "is_possible": True,
                "region_description": "India",
                "country_calling_code": 91,
                "country_code": "IN",
                "number_type": "mobile",
                "international_format": "+91 99178 91298",
                "national_format": "099178 91298",
                "timezones": ["Asia/Calcutta"],
                "assumed_country": "IN",
            },
        ),
        "numverify": IntegrationResult(
            source="numverify",
            status=ModuleResultStatus.SUCCESS,
            data={
                "number": INDIAN_NUMBER_E164,
                "country_name": "India",
                "country_code": 91,
                "international_format": "+91 99178 91298",
                "local_format": "09917891298",
                "carrier": "Some Carrier",
                "line_type": "mobile",
            },
        ),
    }

    overview = service._build_overview(results)

    assert overview["providers_consulted"] == ["phone_validation", "numverify"]
    assert overview["normalized_e164"] == INDIAN_NUMBER_E164
