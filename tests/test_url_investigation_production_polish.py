import asyncio
from unittest.mock import AsyncMock

import pytest

from backend.app.integrations.base import IntegrationResult
from backend.app.integrations.url.http_response_integration import (
    _extract_favicon,
    _extract_title,
)
from backend.app.models.investigation import InvestigationStatus
from backend.app.models.investigation import ModuleResultStatus
from backend.app.services.url_service import URLIntelligenceService
from backend.app.services.url_service import _build_summary
from backend.app.services.url_service import _build_threat_assessment


# ==========================================================
# HttpResponseIntegration pure helpers
# ==========================================================


def test_extract_title_finds_the_page_title():
    html = "<html><head><title>Google</title></head><body></body></html>"
    assert _extract_title(html) == "Google"


def test_extract_title_trims_whitespace():
    assert _extract_title("<title>  Spaced Title  </title>") == "Spaced Title"


def test_extract_title_returns_none_when_absent():
    assert _extract_title("<html><body>no title here</body></html>") is None


def test_extract_favicon_resolves_relative_href():
    html = '<link rel="icon" href="/favicon.png">'
    assert _extract_favicon(html, "https://google.com/") == "https://google.com/favicon.png"


def test_extract_favicon_handles_single_quotes_and_shortcut_variant():
    html = "<link rel='shortcut icon' href='favicon.ico'>"
    assert (
        _extract_favicon(html, "https://example.com/path/")
        == "https://example.com/path/favicon.ico"
    )


def test_extract_favicon_never_fabricates_a_guess_when_absent():
    """
    Must not fall back to guessing /favicon.ico - only report what was
    actually observed in the page.
    """
    assert _extract_favicon("<html><body></body></html>", "https://example.com/") is None


# ==========================================================
# Threat assessment (evidence-backed states, never a bare score)
# ==========================================================


def test_assessment_no_providers_is_incomplete_and_lists_not_implemented_providers():
    result = _build_threat_assessment({})

    assert result.data["state"] == "threat_assessment_incomplete"
    assert result.data["label"] == "Threat assessment incomplete"
    assert "google_safe_browsing" in result.data["providers_unavailable"]
    assert "phishtank" in result.data["providers_unavailable"]
    assert "safe" not in result.data["label"].lower()


def test_assessment_virustotal_malicious_flags_malicious():
    result = _build_threat_assessment(
        {
            "virustotal_url": IntegrationResult(
                "virustotal_url",
                ModuleResultStatus.SUCCESS,
                data={"analysis_stats": {"malicious": 5, "suspicious": 0, "harmless": 90}},
            ),
        }
    )

    assert result.data["state"] == "malicious"
    assert result.data["label"] == "Malicious indicators detected"


def test_assessment_virustotal_suspicious_only_flags_suspicious():
    result = _build_threat_assessment(
        {
            "virustotal_url": IntegrationResult(
                "virustotal_url",
                ModuleResultStatus.SUCCESS,
                data={"analysis_stats": {"malicious": 0, "suspicious": 3, "harmless": 90}},
            ),
        }
    )

    assert result.data["state"] == "suspicious"


def test_assessment_urlscan_malicious_verdict_flags_malicious():
    result = _build_threat_assessment(
        {
            "urlscan": IntegrationResult(
                "urlscan",
                ModuleResultStatus.SUCCESS,
                data={"malicious": True, "verdict_categories": ["phishing"]},
            ),
        }
    )

    assert result.data["state"] == "malicious"
    assert any("phishing" in r for r in result.data["reasoning"])


def test_assessment_clean_results_never_say_safe():
    result = _build_threat_assessment(
        {
            "virustotal_url": IntegrationResult(
                "virustotal_url",
                ModuleResultStatus.SUCCESS,
                data={"analysis_stats": {"malicious": 0, "suspicious": 0, "harmless": 95}},
            ),
            "urlscan": IntegrationResult(
                "urlscan", ModuleResultStatus.SUCCESS, data={"malicious": False}
            ),
        }
    )

    assert result.data["state"] == "no_malicious_evidence_detected"
    assert "safe" not in result.data["label"].lower()


def test_assessment_all_failed_is_insufficient_evidence():
    result = _build_threat_assessment(
        {
            "virustotal_url": IntegrationResult(
                "virustotal_url", ModuleResultStatus.FAILED, error_message="timeout"
            ),
        }
    )

    assert result.data["state"] == "inconclusive"
    assert result.data["label"] == "Insufficient evidence"


# ==========================================================
# Analyst summary
# ==========================================================


def test_build_summary_matches_spec_example():
    assessment = _build_threat_assessment({})

    summary = _build_summary(
        assessment_data=assessment.data,
        results={
            "http_response": IntegrationResult(
                "http_response",
                ModuleResultStatus.SUCCESS,
                data={"final_url": "https://www.google.com", "canonical_host": "google.com"},
            ),
            "ssl_certificate": IntegrationResult(
                "ssl_certificate",
                ModuleResultStatus.SUCCESS,
                data={"certificate_valid": True, "is_expired": False},
            ),
            "dns_lookup": IntegrationResult("dns_lookup", ModuleResultStatus.SUCCESS),
            "whois": IntegrationResult("whois", ModuleResultStatus.SUCCESS),
        },
    )

    assert "URL successfully analyzed." in summary
    assert "resolves to google.com" in summary
    assert "TLS certificate is valid" in summary
    assert "DNS and WHOIS information were successfully collected" in summary
    assert "No threat intelligence providers were configured" in summary
    assert "safe" not in summary.lower()


def test_build_summary_never_says_generic_no_notable_risk_signals():
    assessment = _build_threat_assessment(
        {
            "virustotal_url": IntegrationResult(
                "virustotal_url",
                ModuleResultStatus.SUCCESS,
                data={"analysis_stats": {"malicious": 0, "suspicious": 0}},
            ),
        }
    )

    summary = _build_summary(assessment_data=assessment.data, results={})

    assert "No notable risk signals found" not in summary


# ==========================================================
# Full orchestration: new engines wired in, error isolation
# ==========================================================


def _canned(source: str, status=ModuleResultStatus.SUCCESS, data=None):
    return IntegrationResult(source=source, status=status, data=data or {})


def test_http_response_and_otx_engines_are_wired_into_the_pipeline(db_session, test_user):
    """
    Regression guard for the new engines actually being included in
    the existing concurrent-gather orchestration (additive - no
    restructuring of investigate() itself).

    _URL_SPECIFIC_ENGINES / _DOMAIN_CONTEXT_ENGINES are module-level
    shared singleton instances (unlike domain_service.py's per-
    instance engines) - patch.object + ExitStack ensures every patch
    is restored after this test, regardless of pass/fail, so nothing
    leaks into other tests sharing this process.
    """
    from contextlib import ExitStack
    from unittest.mock import patch

    from backend.app.services import url_service as url_service_module

    with ExitStack() as stack:

        for engine in url_service_module._URL_SPECIFIC_ENGINES:
            stack.enter_context(
                patch.object(engine, "run", AsyncMock(return_value=_canned(engine.source_name)))
            )

        for engine in url_service_module._DOMAIN_CONTEXT_ENGINES:
            stack.enter_context(
                patch.object(engine, "run", AsyncMock(return_value=_canned(engine.source_name)))
            )

        service = URLIntelligenceService(db_session)

        investigation = asyncio.run(
            service.investigate(user_id=test_user.id, url="https://example.com/path")
        )

        sources = {r.source for r in investigation.results}
        assert "http_response" in sources
        assert "otx" in sources
        assert "threat_assessment" in sources

        # Every engine received the target it's meant to receive:
        # domain-context engines get the extracted host, URL-specific
        # engines get the full URL.
        for engine in url_service_module._DOMAIN_CONTEXT_ENGINES:
            engine.run.assert_awaited_once_with("example.com")

        for engine in url_service_module._URL_SPECIFIC_ENGINES:
            engine.run.assert_awaited_once_with("https://example.com/path")


def test_one_provider_failure_does_not_fail_the_whole_investigation(db_session, test_user):
    from contextlib import ExitStack
    from unittest.mock import patch

    from backend.app.services import url_service as url_service_module

    with ExitStack() as stack:

        for i, engine in enumerate(url_service_module._URL_SPECIFIC_ENGINES):
            # First URL-specific engine fails outright; the rest succeed.
            status = ModuleResultStatus.FAILED if i == 0 else ModuleResultStatus.SUCCESS
            stack.enter_context(
                patch.object(
                    engine, "run", AsyncMock(return_value=_canned(engine.source_name, status=status))
                )
            )

        for engine in url_service_module._DOMAIN_CONTEXT_ENGINES:
            stack.enter_context(
                patch.object(engine, "run", AsyncMock(return_value=_canned(engine.source_name)))
            )

        service = URLIntelligenceService(db_session)

        investigation = asyncio.run(
            service.investigate(user_id=test_user.id, url="https://example.com/")
        )

        # The investigation as a whole reflects the mixed outcome
        # (PARTIAL) rather than being marked FAILED outright - one bad
        # provider does not take down the others' results, which are
        # still persisted.
        assert investigation.status == InvestigationStatus.PARTIAL
        assert len(investigation.results) >= len(
            url_service_module._URL_SPECIFIC_ENGINES
        ) + len(url_service_module._DOMAIN_CONTEXT_ENGINES)
