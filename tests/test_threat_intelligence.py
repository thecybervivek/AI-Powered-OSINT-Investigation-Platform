from backend.app.integrations.base import IntegrationResult
from backend.app.models.investigation import InvestigationStatus
from backend.app.models.investigation import ModuleResultStatus
from backend.app.services.threat_intelligence_service import ThreatIntelligenceService


def _service() -> ThreatIntelligenceService:
    # _compute_risk_score/_overall_status/_build_summary touch no
    # database state - same db=None pattern used throughout Milestone 9.
    return ThreatIntelligenceService(db=None)


def _skipped(source: str) -> IntegrationResult:

    return IntegrationResult(
        source=source,
        status=ModuleResultStatus.SKIPPED,
        error_message=f"{source} is not configured.",
    )


# ==========================================================
# _compute_risk_score
# ==========================================================

def test_risk_score_zero_when_everything_skipped():

    service = _service()

    results = {
        "shodan": _skipped("shodan"),
        "censys": _skipped("censys"),
        "greynoise": _skipped("greynoise"),
        "otx": _skipped("otx"),
        "securitytrails": _skipped("securitytrails"),
    }

    score, notes = service._compute_risk_score(results)

    assert score == 0.0
    assert notes == []


def test_risk_score_flags_greynoise_malicious_classification():

    service = _service()

    results = {
        "greynoise": IntegrationResult(
            source="greynoise",
            status=ModuleResultStatus.SUCCESS,
            data={
                "is_internet_noise": True,
                "is_common_business_service": False,
                "classification": "malicious",
            },
        ),
    }

    score, notes = service._compute_risk_score(results)

    assert score == 30
    assert any("malicious internet scanning" in note for note in notes)


def test_risk_score_flags_otx_pulse_count_capped():

    service = _service()

    # 10 pulses * 5 = 50, but capped at high=35.
    results = {
        "otx": IntegrationResult(
            source="otx",
            status=ModuleResultStatus.SUCCESS,
            data={"pulse_count": 10},
        ),
    }

    score, notes = service._compute_risk_score(results)

    assert score == 35
    assert any("10 AlienVault OTX threat pulse" in note for note in notes)


def test_risk_score_flags_shodan_vulnerabilities_and_large_surface():

    service = _service()

    results = {
        "shodan": IntegrationResult(
            source="shodan",
            status=ModuleResultStatus.SUCCESS,
            data={
                "vulnerabilities": ["CVE-2021-1", "CVE-2021-2", "CVE-2021-3"],
                "open_ports": list(range(1, 15)),  # 14 ports >= 10 threshold
            },
        ),
    }

    score, notes = service._compute_risk_score(results)

    # 3 vulns * 4 = 12, plus +10 for >=10 open ports = 22
    assert score == 22
    assert any("3 known CVE" in note for note in notes)
    assert any("14 open ports" in note for note in notes)


def test_riot_flag_reduces_composite_score():
    """
    A GreyNoise RIOT (known common business service) hit should pull the
    composite score down significantly, even when other providers found
    something that would otherwise look concerning - it explains away
    the noise/scan classification rather than stacking on top of it.
    """

    service = _service()

    base_results = {
        "otx": IntegrationResult(
            source="otx",
            status=ModuleResultStatus.SUCCESS,
            data={"pulse_count": 4},  # 4*5=20 points before any RIOT adjustment
        ),
    }

    non_riot_score, _ = service._compute_risk_score(base_results)

    riot_results = {
        **base_results,
        "greynoise": IntegrationResult(
            source="greynoise",
            status=ModuleResultStatus.SUCCESS,
            data={
                "is_internet_noise": True,
                "is_common_business_service": True,
                "classification": "benign",
            },
        ),
    }

    riot_score, riot_notes = service._compute_risk_score(riot_results)

    assert non_riot_score == 20
    assert riot_score == 6.0  # 20 * 0.3, per the documented reduction factor
    assert riot_score < non_riot_score
    assert any("RIOT" in note for note in riot_notes)


def test_riot_true_does_not_double_count_noise_classification():
    """
    When GreyNoise says both noise=True AND riot=True, the malicious/
    unknown-classification scoring branch must NOT fire (is_riot gates
    it off) - only the RIOT reduction should apply.
    """

    service = _service()

    results = {
        "greynoise": IntegrationResult(
            source="greynoise",
            status=ModuleResultStatus.SUCCESS,
            data={
                "is_internet_noise": True,
                "is_common_business_service": True,
                "classification": "malicious",  # should be ignored when riot=True
            },
        ),
    }

    score, notes = service._compute_risk_score(results)

    assert score == 0.0  # 0 * 0.3 = 0, no malicious-classification points added
    assert not any("malicious internet scanning" in note for note in notes)
    assert any("RIOT" in note for note in notes)


# ==========================================================
# _overall_status
# ==========================================================

def test_overall_status_failed_when_all_providers_skipped():

    service = _service()

    results = [_skipped(name) for name in ("shodan", "censys", "greynoise", "otx", "securitytrails")]

    assert service._overall_status(results) == InvestigationStatus.FAILED


def test_overall_status_partial_when_one_provider_fails():

    service = _service()

    results = [
        IntegrationResult(source="shodan", status=ModuleResultStatus.SUCCESS, data={}),
        IntegrationResult(source="censys", status=ModuleResultStatus.FAILED, error_message="boom"),
        _skipped("greynoise"),
    ]

    assert service._overall_status(results) == InvestigationStatus.PARTIAL


def test_overall_status_completed_when_configured_providers_succeed():

    service = _service()

    results = [
        IntegrationResult(source="shodan", status=ModuleResultStatus.SUCCESS, data={}),
        IntegrationResult(source="greynoise", status=ModuleResultStatus.NOT_FOUND, data={}),
        _skipped("censys"),
        _skipped("otx"),
        _skipped("securitytrails"),
    ]

    assert service._overall_status(results) == InvestigationStatus.COMPLETED


# ==========================================================
# _build_summary
# ==========================================================

def test_build_summary_no_findings():

    service = _service()

    summary = service._build_summary("example.com", "93.184.216.34", risk_notes=[])

    assert "No notable threat signals" in summary
    assert "example.com" in summary
    assert "93.184.216.34" in summary


def test_build_summary_ip_target_omits_resolution_note():

    service = _service()

    summary = service._build_summary(
        "93.184.216.34",
        "93.184.216.34",
        risk_notes=["Referenced in 4 AlienVault OTX threat pulse(s)"],
    )

    assert "resolved to" not in summary
    assert "Referenced in 4 AlienVault OTX threat pulse" in summary
