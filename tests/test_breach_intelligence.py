from backend.app.integrations.base import IntegrationResult
from backend.app.models.investigation import InvestigationStatus
from backend.app.models.investigation import ModuleResultStatus
from backend.app.services.breach_service import BreachIntelligenceService


def _service() -> BreachIntelligenceService:
    # _build_breach_summary/_compute_risk_score/_overall_status/
    # _build_summary touch no database state - same db=None pattern as
    # every other Milestone 9 service test.
    return BreachIntelligenceService(db=None)


# ==========================================================
# _build_breach_summary
# ==========================================================

def test_breach_summary_empty_when_nothing_found():

    service = _service()

    results = {
        "hibp": IntegrationResult(
            source="hibp",
            status=ModuleResultStatus.NOT_FOUND,
            data={"email": "clean@example.com", "breached": False, "breach_count": 0, "breaches": []},
        ),
        "dehashed": IntegrationResult(
            source="dehashed",
            status=ModuleResultStatus.SKIPPED,
            error_message="DeHashed is not configured.",
        ),
        "emailrep": IntegrationResult(
            source="emailrep",
            status=ModuleResultStatus.SUCCESS,
            data={"data_breach": False, "credentials_leaked": False},
        ),
    }

    summary = service._build_breach_summary("clean@example.com", True, results)

    assert summary["total_breaches"] == 0
    assert summary["password_exposure_status"] == "not_exposed"
    assert summary["local_fallback_used"] is False
    assert summary["exposed_emails"] == []
    assert summary["breach_timeline"] == []


def test_breach_summary_builds_timeline_from_hibp():

    service = _service()

    results = {
        "hibp": IntegrationResult(
            source="hibp",
            status=ModuleResultStatus.SUCCESS,
            data={
                "email": "victim@example.com",
                "breached": True,
                "breach_count": 2,
                "breaches": [
                    {
                        "name": "OldBreach",
                        "domain": "old.example",
                        "breach_date": "2019-01-01",
                        "data_classes": ["Email addresses"],
                        "is_sensitive": False,
                    },
                    {
                        "name": "NewBreach",
                        "domain": "new.example",
                        "breach_date": "2023-06-15",
                        "data_classes": ["Passwords"],
                        "is_sensitive": True,
                    },
                ],
            },
        ),
        "dehashed": IntegrationResult(
            source="dehashed",
            status=ModuleResultStatus.SKIPPED,
            error_message="DeHashed is not configured.",
        ),
        "emailrep": IntegrationResult(
            source="emailrep",
            status=ModuleResultStatus.SUCCESS,
            data={"data_breach": True, "credentials_leaked": False},
        ),
    }

    summary = service._build_breach_summary("victim@example.com", True, results)

    assert summary["total_breaches"] == 2
    assert summary["breach_names"] == ["NewBreach", "OldBreach"]
    assert summary["exposed_domains"] == ["new.example", "old.example"]
    assert summary["password_exposure_status"] == "confirmed_breached_hibp"

    # Most recent breach first.
    assert summary["breach_timeline"][0]["breach_name"] == "NewBreach"
    assert summary["breach_timeline"][1]["breach_name"] == "OldBreach"


def test_breach_summary_dehashed_plaintext_takes_priority_over_hibp():

    service = _service()

    results = {
        "hibp": IntegrationResult(
            source="hibp",
            status=ModuleResultStatus.SUCCESS,
            data={"email": "x@example.com", "breached": True, "breach_count": 1, "breaches": [
                {"name": "SomeBreach", "domain": "some.example", "breach_date": "2020-01-01",
                 "data_classes": [], "is_sensitive": False},
            ]},
        ),
        "dehashed": IntegrationResult(
            source="dehashed",
            status=ModuleResultStatus.SUCCESS,
            data={
                "query": "email:x@example.com",
                "total_entries": 1,
                "exposed_emails": ["x@example.com"],
                "exposed_domains": ["example.com"],
                "breached_databases": ["SomeDump"],
                "has_plaintext_password_exposure": True,
                "has_hashed_password_exposure": False,
                "entries": [],
            },
        ),
        "emailrep": IntegrationResult(
            source="emailrep",
            status=ModuleResultStatus.SUCCESS,
            data={"data_breach": True, "credentials_leaked": True},
        ),
    }

    summary = service._build_breach_summary("x@example.com", True, results)

    assert summary["password_exposure_status"] == "confirmed_plaintext"
    assert summary["local_fallback_used"] is False  # not needed - real sources answered


def test_breach_summary_uses_local_fallback_when_no_keys_configured():

    service = _service()

    results = {
        "hibp": IntegrationResult(
            source="hibp",
            status=ModuleResultStatus.SKIPPED,
            error_message="HIBP is not configured.",
        ),
        "dehashed": IntegrationResult(
            source="dehashed",
            status=ModuleResultStatus.SKIPPED,
            error_message="DeHashed is not configured.",
        ),
        "emailrep": IntegrationResult(
            source="emailrep",
            status=ModuleResultStatus.SUCCESS,
            data={"data_breach": True, "credentials_leaked": False},
        ),
    }

    summary = service._build_breach_summary("noapikeys@example.com", True, results)

    assert summary["local_fallback_used"] is True
    assert summary["password_exposure_status"] == "possibly_exposed_local_signal"
    assert "noapikeys@example.com" in summary["exposed_emails"]


def test_breach_summary_domain_target_skips_email_only_sources():

    service = _service()

    results = {
        "dehashed": IntegrationResult(
            source="dehashed",
            status=ModuleResultStatus.SUCCESS,
            data={
                "query": "domain:example.com",
                "total_entries": 2,
                "exposed_emails": ["a@example.com", "b@example.com"],
                "exposed_domains": ["example.com"],
                "breached_databases": ["BigDump"],
                "has_plaintext_password_exposure": False,
                "has_hashed_password_exposure": True,
                "entries": [],
            },
        ),
    }

    summary = service._build_breach_summary("example.com", False, results)

    assert summary["is_email"] is False
    assert summary["exposed_emails"] == ["a@example.com", "b@example.com"]
    assert summary["password_exposure_status"] == "confirmed_hashed"


# ==========================================================
# _compute_risk_score
# ==========================================================

def test_risk_score_zero_when_no_breaches():

    service = _service()

    score, notes = service._compute_risk_score(
        {"total_breaches": 0, "password_exposure_status": "not_exposed"}
    )

    assert score == 0.0
    assert notes == []


def test_risk_score_highest_for_plaintext_exposure():

    service = _service()

    plaintext_score, _ = service._compute_risk_score(
        {"total_breaches": 1, "password_exposure_status": "confirmed_plaintext"}
    )
    hashed_score, _ = service._compute_risk_score(
        {"total_breaches": 1, "password_exposure_status": "confirmed_hashed"}
    )
    hibp_only_score, _ = service._compute_risk_score(
        {"total_breaches": 1, "password_exposure_status": "confirmed_breached_hibp"}
    )
    local_signal_score, _ = service._compute_risk_score(
        {"total_breaches": 0, "password_exposure_status": "possibly_exposed_local_signal"}
    )

    assert plaintext_score > hashed_score > hibp_only_score > 0
    assert local_signal_score > 0
    assert local_signal_score < hibp_only_score


# ==========================================================
# _overall_status
# ==========================================================

def test_overall_status_failed_when_everything_skipped():

    service = _service()

    results = [
        IntegrationResult(source="hibp", status=ModuleResultStatus.SKIPPED),
        IntegrationResult(source="dehashed", status=ModuleResultStatus.SKIPPED),
    ]

    assert service._overall_status(results) == InvestigationStatus.FAILED


def test_overall_status_partial_when_one_source_fails():

    service = _service()

    results = [
        IntegrationResult(source="hibp", status=ModuleResultStatus.SUCCESS, data={}),
        IntegrationResult(source="dehashed", status=ModuleResultStatus.FAILED, error_message="boom"),
    ]

    assert service._overall_status(results) == InvestigationStatus.PARTIAL


def test_overall_status_completed_when_all_succeed_or_skip():

    service = _service()

    results = [
        IntegrationResult(source="hibp", status=ModuleResultStatus.SUCCESS, data={}),
        IntegrationResult(source="dehashed", status=ModuleResultStatus.SKIPPED),
        IntegrationResult(source="emailrep", status=ModuleResultStatus.NOT_FOUND, data={}),
    ]

    assert service._overall_status(results) == InvestigationStatus.COMPLETED


# ==========================================================
# _build_summary
# ==========================================================

def test_build_summary_no_findings():

    service = _service()

    summary = service._build_summary(
        "clean@example.com",
        {"total_breaches": 0},
        risk_notes=[],
    )

    assert "No breach exposure found" in summary
    assert "clean@example.com" in summary


def test_build_summary_joins_notes():

    service = _service()

    summary = service._build_summary(
        "victim@example.com",
        {"total_breaches": 2},
        risk_notes=["Found in 2 known breach(es)/dataset(s)"],
    )

    assert "Found in 2 known breach" in summary
    assert "victim@example.com" in summary
