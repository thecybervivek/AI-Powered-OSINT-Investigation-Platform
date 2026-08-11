import asyncio
from unittest.mock import AsyncMock
from unittest.mock import patch

import httpx

from backend.app.integrations.base import IntegrationResult
from backend.app.integrations.email.account_presence import AccountPresenceState
from backend.app.integrations.email.account_presence import PlatformPresenceResult
from backend.app.integrations.email.account_presence import _check_github
from backend.app.integrations.email.account_presence import _check_soundcloud
from backend.app.integrations.email.account_presence import _make_blocked_platform
from backend.app.integrations.email.account_presence import default_presence_platforms
from backend.app.integrations.email.account_presence import run_presence_checks
from backend.app.integrations.email.ghunt_integration import GHuntIntegration
from backend.app.integrations.email.holehe_integration import HoleheIntegration
from backend.app.models.investigation import ModuleResultStatus
from backend.app.services.email_service import EmailIntelligenceService


def _canned(source: str, status=ModuleResultStatus.SUCCESS, data=None) -> IntegrationResult:
    return IntegrationResult(source=source, status=status, data=data or {})


def _presence(platform: str, status: AccountPresenceState, **overrides) -> PlatformPresenceResult:
    defaults = dict(
        platform=platform, domain=f"{platform}.com", category="test",
        status=status, confidence="high" if status in (
            AccountPresenceState.CONFIRMED, AccountPresenceState.NOT_FOUND
        ) else "low",
        evidence="test evidence", http_status=200, checked_at="2026-08-01T00:00:00+00:00",
    )
    defaults.update(overrides)
    return PlatformPresenceResult(**defaults)


def _service() -> EmailIntelligenceService:
    return EmailIntelligenceService(db=None)


# ==========================================================
# account_presence.py — per-platform checker response mapping
# (unchanged behavior from prior rounds, re-verified against the
# renamed `status` field and new confidence/evidence/checked_at model)
# ==========================================================


def test_github_422_maps_to_confirmed():
    join_html = '<auto-check src="/signup_check/email" ...authenticity_token" value="tok123">'
    join_response = httpx.Response(200, text=join_html, request=httpx.Request("GET", "https://github.com/join"))
    check_response = httpx.Response(422, request=httpx.Request("POST", "https://github.com/signup_check/email"))

    with patch(
        "backend.app.integrations.email.account_presence.request_with_retry",
        new=AsyncMock(side_effect=[join_response, check_response]),
    ), patch("backend.app.integrations.email.account_presence.assert_public_url"):
        result = asyncio.run(_check_github(httpx.AsyncClient(), "someone@example.com"))

    assert result.status == AccountPresenceState.CONFIRMED
    assert result.confidence == "high"
    assert result.evidence
    assert result.checked_at


def test_github_200_maps_to_not_found():
    join_html = '<auto-check src="/signup_check/email" ...authenticity_token" value="tok123">'
    join_response = httpx.Response(200, text=join_html, request=httpx.Request("GET", "https://github.com/join"))
    check_response = httpx.Response(200, request=httpx.Request("POST", "https://github.com/signup_check/email"))

    with patch(
        "backend.app.integrations.email.account_presence.request_with_retry",
        new=AsyncMock(side_effect=[join_response, check_response]),
    ), patch("backend.app.integrations.email.account_presence.assert_public_url"):
        result = asyncio.run(_check_github(httpx.AsyncClient(), "someone@example.com"))

    assert result.status == AccountPresenceState.NOT_FOUND


def test_github_missing_token_is_unknown_not_not_found():
    join_response = httpx.Response(200, text="<html>no auto-check here</html>", request=httpx.Request("GET", "https://github.com/join"))

    with patch(
        "backend.app.integrations.email.account_presence.request_with_retry",
        new=AsyncMock(return_value=join_response),
    ), patch("backend.app.integrations.email.account_presence.assert_public_url"):
        result = asyncio.run(_check_github(httpx.AsyncClient(), "someone@example.com"))

    assert result.status == AccountPresenceState.UNKNOWN


def test_github_429_maps_to_rate_limited():
    join_html = '<auto-check src="/signup_check/email" ...authenticity_token" value="tok123">'
    join_response = httpx.Response(200, text=join_html, request=httpx.Request("GET", "https://github.com/join"))
    check_response = httpx.Response(429, request=httpx.Request("POST", "https://github.com/signup_check/email"))

    with patch(
        "backend.app.integrations.email.account_presence.request_with_retry",
        new=AsyncMock(side_effect=[join_response, check_response]),
    ), patch("backend.app.integrations.email.account_presence.assert_public_url"):
        result = asyncio.run(_check_github(httpx.AsyncClient(), "someone@example.com"))

    assert result.status == AccountPresenceState.RATE_LIMITED


def test_github_network_error_maps_to_failed_never_not_found():
    with patch(
        "backend.app.integrations.email.account_presence.request_with_retry",
        new=AsyncMock(side_effect=httpx.ConnectError("boom")),
    ), patch("backend.app.integrations.email.account_presence.assert_public_url"):
        result = asyncio.run(_check_github(httpx.AsyncClient(), "someone@example.com"))

    assert result.status == AccountPresenceState.FAILED
    assert result.status != AccountPresenceState.NOT_FOUND


def test_soundcloud_in_use_maps_to_confirmed():
    response = httpx.Response(200, json={"status": "in_use"}, request=httpx.Request("GET", "https://api-auth.soundcloud.com/x"))

    with patch(
        "backend.app.integrations.email.account_presence.request_with_retry",
        new=AsyncMock(return_value=response),
    ), patch("backend.app.integrations.email.account_presence.assert_public_url"):
        result = asyncio.run(_check_soundcloud(httpx.AsyncClient(), "someone@example.com"))

    assert result.status == AccountPresenceState.CONFIRMED


def test_soundcloud_available_maps_to_not_found():
    response = httpx.Response(200, json={"status": "available"}, request=httpx.Request("GET", "https://api-auth.soundcloud.com/x"))

    with patch(
        "backend.app.integrations.email.account_presence.request_with_retry",
        new=AsyncMock(return_value=response),
    ), patch("backend.app.integrations.email.account_presence.assert_public_url"):
        result = asyncio.run(_check_soundcloud(httpx.AsyncClient(), "someone@example.com"))

    assert result.status == AccountPresenceState.NOT_FOUND


def test_soundcloud_401_never_maps_to_not_found():
    response = httpx.Response(401, request=httpx.Request("GET", "https://api-auth.soundcloud.com/x"))

    with patch(
        "backend.app.integrations.email.account_presence.request_with_retry",
        new=AsyncMock(return_value=response),
    ), patch("backend.app.integrations.email.account_presence.assert_public_url"):
        result = asyncio.run(_check_soundcloud(httpx.AsyncClient(), "someone@example.com"))

    assert result.status != AccountPresenceState.NOT_FOUND
    assert result.status == AccountPresenceState.UNKNOWN


def test_soundcloud_network_error_maps_to_failed():
    with patch(
        "backend.app.integrations.email.account_presence.request_with_retry",
        new=AsyncMock(side_effect=httpx.ConnectError("boom")),
    ), patch("backend.app.integrations.email.account_presence.assert_public_url"):
        result = asyncio.run(_check_soundcloud(httpx.AsyncClient(), "someone@example.com"))

    assert result.status == AccountPresenceState.FAILED


# ==========================================================
# BLOCKED-by-design platforms (Instagram/LinkedIn) — never fake a
# working check, never silently omit, never call NOT_FOUND
# ==========================================================


def test_blocked_by_design_platform_never_makes_a_network_call():
    platform = _make_blocked_platform("instagram", "instagram.com", "anti-bot controls")

    with patch(
        "backend.app.integrations.email.account_presence.request_with_retry",
        new=AsyncMock(side_effect=AssertionError("must not call the network")),
    ):
        result = asyncio.run(platform.checker(httpx.AsyncClient(), "someone@example.com"))

    assert result.status == AccountPresenceState.BLOCKED
    assert result.provider_reason == "anti-bot controls"
    assert result.status != AccountPresenceState.NOT_FOUND


def test_default_platforms_include_the_two_working_checks_and_two_blocked_stubs():
    platforms = default_presence_platforms()
    names = {p.name for p in platforms}
    assert {"github", "soundcloud", "instagram", "linkedin"} == names


def test_run_presence_checks_never_produces_not_found_for_blocked_platform():
    checks = asyncio.run(run_presence_checks("someone@example.com", default_presence_platforms()[2:]))
    assert all(c.status != AccountPresenceState.NOT_FOUND for c in checks)


# ==========================================================
# HoleheIntegration — aggregation / status precedence
# ==========================================================


def test_holehe_confirmed_beats_inconclusive_others():
    checks = [
        _presence("github", AccountPresenceState.CONFIRMED),
        _presence("soundcloud", AccountPresenceState.UNKNOWN),
    ]

    integration = HoleheIntegration()

    with patch(
        "backend.app.integrations.email.holehe_integration.run_presence_checks",
        new=AsyncMock(return_value=checks),
    ):
        result = asyncio.run(integration._query("someone@example.com"))

    assert result.status == ModuleResultStatus.SUCCESS
    assert result.data["accounts_confirmed"] == 1
    assert result.data["results"][0]["confidence"] == "high"
    assert result.data["results"][0]["checked_at"]


def test_holehe_all_not_found_is_not_found_not_failed():
    checks = [
        _presence("github", AccountPresenceState.NOT_FOUND),
        _presence("soundcloud", AccountPresenceState.NOT_FOUND),
    ]

    integration = HoleheIntegration()

    with patch(
        "backend.app.integrations.email.holehe_integration.run_presence_checks",
        new=AsyncMock(return_value=checks),
    ):
        result = asyncio.run(integration._query("someone@example.com"))

    assert result.status == ModuleResultStatus.NOT_FOUND


def test_holehe_all_blocked_or_rate_limited_is_rate_limited_not_failed():
    checks = [
        _presence("instagram", AccountPresenceState.BLOCKED),
        _presence("github", AccountPresenceState.RATE_LIMITED),
    ]

    integration = HoleheIntegration()

    with patch(
        "backend.app.integrations.email.holehe_integration.run_presence_checks",
        new=AsyncMock(return_value=checks),
    ):
        result = asyncio.run(integration._query("someone@example.com"))

    assert result.status == ModuleResultStatus.RATE_LIMITED


def test_holehe_invalid_email_fails_without_network_call():
    integration = HoleheIntegration()
    result = asyncio.run(integration._query("not-an-email"))
    assert result.status == ModuleResultStatus.FAILED


# ==========================================================
# GHuntIntegration — disabled-by-default, never fabricates SAFE
# ==========================================================


def test_ghunt_skipped_by_default():
    integration = GHuntIntegration()
    assert integration.is_configured() is False

    result = asyncio.run(integration.run("someone@example.com"))

    assert result.status == ModuleResultStatus.SKIPPED


# ==========================================================
# EmailIntelligenceService._merge_account_presence — dedup + no
# fabricated profile URLs
# ==========================================================


def test_merge_account_presence_never_fabricates_a_profile_url():
    results = {
        "holehe": _canned(
            "holehe",
            data={"results": [{
                "platform": "github", "domain": "github.com", "category": "developer",
                "status": "confirmed", "confidence": "high", "evidence": "e",
                "checked_at": "t", "provider_reason": None, "profile_url": None,
            }]},
        ),
    }

    merged = _service()._merge_account_presence(results)
    assert merged[0]["profile_url"] is None


def test_merge_account_presence_passes_through_a_real_profile_url():
    results = {
        "holehe": _canned(
            "holehe",
            data={"results": [{
                "platform": "examplesite", "domain": "example.com", "category": "test",
                "status": "confirmed", "confidence": "high", "evidence": "e",
                "checked_at": "t", "provider_reason": None,
                "profile_url": "https://example.com/u/someone",
            }]},
        ),
    }

    merged = _service()._merge_account_presence(results)
    assert merged[0]["profile_url"] == "https://example.com/u/someone"


def test_merge_account_presence_deduplicates_across_sources():
    results = {
        "holehe": _canned(
            "holehe",
            data={"results": [{
                "platform": "github", "domain": "github.com", "category": "developer",
                "status": "not_found", "confidence": "high", "evidence": "e1",
                "checked_at": "t", "provider_reason": None, "profile_url": None,
            }]},
        ),
    }

    service = _service()

    with patch(
        "backend.app.services.email_service._ACCOUNT_PRESENCE_SOURCES",
        {"holehe", "other_presence_provider"},
    ):
        results["other_presence_provider"] = _canned(
            "other_presence_provider",
            data={"results": [{
                "platform": "github", "domain": "github.com", "category": "developer",
                "status": "confirmed", "confidence": "high", "evidence": "e2",
                "checked_at": "t", "provider_reason": None, "profile_url": None,
            }]},
        )

        merged = service._merge_account_presence(results)

    assert len(merged) == 1
    assert merged[0]["status"] == "confirmed"
    assert merged[0]["evidence"] == "e2"  # the confirming source's own evidence, not the stale one
    assert set(merged[0]["sources"]) == {"holehe", "other_presence_provider"}


# ==========================================================
# Risk scoring — account presence and inconclusive statuses never
# contribute; breach evidence still does, via the existing engine
# ==========================================================


def test_account_presence_alone_does_not_raise_risk_score():
    results = {
        "holehe": _canned(
            "holehe",
            data={"results": [
                {"platform": "github", "status": "confirmed"},
                {"platform": "soundcloud", "status": "confirmed"},
            ]},
        ),
    }
    score, notes = _service()._compute_risk_score(results)
    assert score == 0.0
    assert notes == []


def test_blocked_and_unknown_account_presence_do_not_raise_risk():
    results = {
        "holehe": _canned(
            "holehe",
            status=ModuleResultStatus.RATE_LIMITED,
            data={"results": [
                {"platform": "instagram", "status": "blocked"},
                {"platform": "github", "status": "unknown"},
            ]},
        ),
    }
    score, notes = _service()._compute_risk_score(results)
    assert score == 0.0
    assert notes == []


def test_confirmed_breach_still_contributes_to_risk_via_existing_engine():
    results = {"hibp": _canned("hibp", data={"breach_count": 2, "contains_sensitive_breach": False})}
    score, notes = _service()._compute_risk_score(results)
    assert score > 0
    assert any("breach" in n for n in notes)


def test_failed_provider_does_not_increase_risk():
    results = {
        "hibp": _canned("hibp", status=ModuleResultStatus.FAILED),
        "emailrep": _canned("emailrep", status=ModuleResultStatus.FAILED),
    }
    score, notes = _service()._compute_risk_score(results)
    assert score == 0.0
    assert notes == []


def test_skipped_provider_does_not_increase_risk():
    results = {"google_intelligence": _canned("google_intelligence", status=ModuleResultStatus.SKIPPED)}
    score, notes = _service()._compute_risk_score(results)
    assert score == 0.0
    assert notes == []


def test_rate_limited_provider_does_not_increase_risk():
    results = {"hibp": _canned("hibp", status=ModuleResultStatus.RATE_LIMITED)}
    score, notes = _service()._compute_risk_score(results)
    assert score == 0.0
    assert notes == []


# ==========================================================
# Summary — the 4 distinguished cases (section 14)
# ==========================================================


def test_summary_case_a_no_breach_no_accounts():
    service = _service()
    summary = service._build_summary("x@example.com", {"hibp": _canned("hibp", data={"breach_count": 0})}, [], [])
    assert "No notable risk signals" in summary


def test_summary_case_b_accounts_found_no_risk():
    service = _service()
    account_presence = [{"platform": "github", "status": "confirmed"}]
    results = {"hibp": _canned("hibp", data={"breach_count": 0})}
    summary = service._build_summary("x@example.com", results, [], account_presence)
    assert "Public account associations were identified" in summary
    assert "no confirmed security risk" in summary


def test_summary_case_c_breach_found_leads_the_summary():
    service = _service()
    results = {"hibp": _canned("hibp", data={"breach_count": 1})}
    risk_notes = ["1 known data breach(es)"]
    summary = service._build_summary("x@example.com", results, risk_notes, [])
    assert "Confirmed breach exposure" in summary
    assert "no breach found" not in summary.lower()


def test_summary_case_c_mentions_accounts_alongside_breach():
    service = _service()
    results = {"hibp": _canned("hibp", data={"breach_count": 1})}
    risk_notes = ["1 known data breach(es)"]
    account_presence = [{"platform": "github", "status": "confirmed"}]
    summary = service._build_summary("x@example.com", results, risk_notes, account_presence)
    assert "Confirmed breach exposure" in summary
    assert "github" in summary


def test_summary_case_d_unavailable_provider_is_not_phrased_as_clean():
    service = _service()
    results = {
        "hibp": _canned("hibp", status=ModuleResultStatus.SKIPPED),
        "emailrep": _canned("emailrep", status=ModuleResultStatus.FAILED),
    }
    summary = service._build_summary("x@example.com", results, [], [])
    assert "unavailable" in summary
    assert "no breach found" not in summary.lower()
    assert "No notable risk signals" not in summary


# ==========================================================
# Persisted risk_assessment / account_presence_summary rows
# ==========================================================


def test_investigate_persists_risk_assessment_and_presence_summary_rows():

    class _FakeRepository:
        def __init__(self):
            self.added = []

        def create(self, investigation):
            investigation.id = "inv-1"
            return investigation

        def add_result(self, result):
            self.added.append(result)

        def update(self, investigation, **kwargs):
            for key, value in kwargs.items():
                setattr(investigation, key, value)
            return investigation

    service = _service()
    service.repository = _FakeRepository()

    async def _fake_run(self, email):
        return _canned(self.source_name, ModuleResultStatus.SKIPPED)

    with patch("backend.app.integrations.base.AsyncBaseIntegration.run", new=_fake_run):
        investigation = asyncio.run(service.investigate(user_id="u1", email="x@example.com"))

    sources = [r.source for r in service.repository.added]
    assert "risk_assessment" in sources
    assert "account_presence_summary" in sources

    risk_row = next(r for r in service.repository.added if r.source == "risk_assessment")
    assert set(risk_row.data.keys()) == {"risk_score", "risk_level", "contributing_evidence"}
    assert risk_row.data["risk_score"] == investigation.risk_score

    presence_row = next(r for r in service.repository.added if r.source == "account_presence_summary")
    assert presence_row.data["platforms"] == []


# ==========================================================
# Breach Intelligence data shape sanity (consumed directly by the
# frontend from the existing hibp result - no new backend model here,
# these just pin the shape the UI depends on)
# ==========================================================


def test_hibp_breach_rows_carry_password_and_sensitive_indicators_not_raw_values():
    breaches = [
        {
            "name": "ExampleBreach", "domain": "example.com", "breach_date": "2024-05-01",
            "data_classes": ["Email addresses", "Passwords"], "is_sensitive": True,
        },
        {
            "name": "OtherBreach", "domain": "other.com", "breach_date": "2022-01-01",
            "data_classes": ["Email addresses"], "is_sensitive": False,
        },
    ]

    for breach in breaches:
        assert "password" not in {k.lower() for k in breach if k != "data_classes"}
        assert all(not isinstance(v, str) or "$" not in v for v in breach.values() if isinstance(v, str))

    password_breach = breaches[0]
    assert any("password" in c.lower() for c in password_breach["data_classes"])
    assert password_breach["is_sensitive"] is True
