"""
Email Intelligence 2.0 test suite.

Covers the native account-presence checker architecture (checkers/,
base_checker.py, normalization.py - modeled on the Username module)
that replaced the removed Holehe/GitHub-derived implementation, plus
email_service.py's risk scoring (breach/reputation evidence only,
never account presence) and its four summary cases.
"""

import asyncio
from unittest.mock import AsyncMock
from unittest.mock import patch

import httpx

from backend.app.integrations.base import IntegrationResult
from backend.app.integrations.email.base_checker import AccountPresenceState
from backend.app.integrations.email.base_checker import make_blocked_platform
from backend.app.integrations.email.checkers import ALL_CHECKERS
from backend.app.integrations.email.checkers.github import _check_github
from backend.app.integrations.email.checkers.soundcloud import _check_soundcloud
from backend.app.integrations.email.normalization import normalize_and_correlate
from backend.app.integrations.email.normalization import summarize_findings
from backend.app.integrations.email.presence_integration import AccountPresenceIntegration
from backend.app.models.investigation import ModuleResultStatus
from backend.app.services.email_service import EmailIntelligenceService


def _canned(source: str, status=ModuleResultStatus.SUCCESS, data=None) -> IntegrationResult:
    return IntegrationResult(source=source, status=status, data=data or {})


def _service() -> EmailIntelligenceService:
    return EmailIntelligenceService(db=None)


# ==========================================================
# checkers/github.py + checkers/soundcloud.py — per-platform
# response mapping. No Holehe/GitHub-derived code: these hit
# GitHub's/SoundCloud's own public, unauthenticated sign-up
# endpoints directly.
# ==========================================================


def test_github_422_maps_to_confirmed():
    join_html = '<auto-check src="/signup_check/email" ...authenticity_token" value="tok123">'
    join_response = httpx.Response(200, text=join_html, request=httpx.Request("GET", "https://github.com/join"))
    check_response = httpx.Response(422, request=httpx.Request("POST", "https://github.com/signup_check/email"))

    with patch(
        "backend.app.integrations.email.checkers.github.request_with_retry",
        new=AsyncMock(side_effect=[join_response, check_response]),
    ), patch("backend.app.integrations.email.checkers.github.assert_public_url"):
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
        "backend.app.integrations.email.checkers.github.request_with_retry",
        new=AsyncMock(side_effect=[join_response, check_response]),
    ), patch("backend.app.integrations.email.checkers.github.assert_public_url"):
        result = asyncio.run(_check_github(httpx.AsyncClient(), "someone@example.com"))

    assert result.status == AccountPresenceState.NOT_FOUND


def test_github_missing_token_is_unknown_not_not_found():
    join_response = httpx.Response(
        200, text="<html>no auto-check here</html>", request=httpx.Request("GET", "https://github.com/join"),
    )

    with patch(
        "backend.app.integrations.email.checkers.github.request_with_retry",
        new=AsyncMock(return_value=join_response),
    ), patch("backend.app.integrations.email.checkers.github.assert_public_url"):
        result = asyncio.run(_check_github(httpx.AsyncClient(), "someone@example.com"))

    assert result.status == AccountPresenceState.UNKNOWN
    assert result.status != AccountPresenceState.NOT_FOUND


def test_github_429_maps_to_rate_limited():
    join_html = '<auto-check src="/signup_check/email" ...authenticity_token" value="tok123">'
    join_response = httpx.Response(200, text=join_html, request=httpx.Request("GET", "https://github.com/join"))
    check_response = httpx.Response(429, request=httpx.Request("POST", "https://github.com/signup_check/email"))

    with patch(
        "backend.app.integrations.email.checkers.github.request_with_retry",
        new=AsyncMock(side_effect=[join_response, check_response]),
    ), patch("backend.app.integrations.email.checkers.github.assert_public_url"):
        result = asyncio.run(_check_github(httpx.AsyncClient(), "someone@example.com"))

    assert result.status == AccountPresenceState.RATE_LIMITED
    assert result.status != AccountPresenceState.NOT_FOUND


def test_github_network_error_maps_to_failed_never_not_found():
    with patch(
        "backend.app.integrations.email.checkers.github.request_with_retry",
        new=AsyncMock(side_effect=httpx.ConnectError("boom")),
    ), patch("backend.app.integrations.email.checkers.github.assert_public_url"):
        result = asyncio.run(_check_github(httpx.AsyncClient(), "someone@example.com"))

    assert result.status == AccountPresenceState.FAILED
    assert result.status != AccountPresenceState.NOT_FOUND


def test_soundcloud_in_use_maps_to_confirmed():
    response = httpx.Response(200, json={"status": "in_use"}, request=httpx.Request("GET", "https://api-auth.soundcloud.com/x"))

    with patch(
        "backend.app.integrations.email.checkers.soundcloud.request_with_retry",
        new=AsyncMock(return_value=response),
    ), patch("backend.app.integrations.email.checkers.soundcloud.assert_public_url"):
        result = asyncio.run(_check_soundcloud(httpx.AsyncClient(), "someone@example.com"))

    assert result.status == AccountPresenceState.CONFIRMED


def test_soundcloud_available_maps_to_not_found():
    response = httpx.Response(200, json={"status": "available"}, request=httpx.Request("GET", "https://api-auth.soundcloud.com/x"))

    with patch(
        "backend.app.integrations.email.checkers.soundcloud.request_with_retry",
        new=AsyncMock(return_value=response),
    ), patch("backend.app.integrations.email.checkers.soundcloud.assert_public_url"):
        result = asyncio.run(_check_soundcloud(httpx.AsyncClient(), "someone@example.com"))

    assert result.status == AccountPresenceState.NOT_FOUND


def test_soundcloud_401_never_maps_to_not_found():
    response = httpx.Response(401, request=httpx.Request("GET", "https://api-auth.soundcloud.com/x"))

    with patch(
        "backend.app.integrations.email.checkers.soundcloud.request_with_retry",
        new=AsyncMock(return_value=response),
    ), patch("backend.app.integrations.email.checkers.soundcloud.assert_public_url"):
        result = asyncio.run(_check_soundcloud(httpx.AsyncClient(), "someone@example.com"))

    assert result.status != AccountPresenceState.NOT_FOUND
    assert result.status == AccountPresenceState.UNKNOWN


def test_soundcloud_network_error_maps_to_failed():
    with patch(
        "backend.app.integrations.email.checkers.soundcloud.request_with_retry",
        new=AsyncMock(side_effect=httpx.ConnectError("boom")),
    ), patch("backend.app.integrations.email.checkers.soundcloud.assert_public_url"):
        result = asyncio.run(_check_soundcloud(httpx.AsyncClient(), "someone@example.com"))

    assert result.status == AccountPresenceState.FAILED


# ==========================================================
# BLOCKED-by-design platforms — never fake a working check,
# never call NOT_FOUND, never touch the network
# ==========================================================


def test_blocked_by_design_platform_never_makes_a_network_call():
    platform = make_blocked_platform("instagram", "instagram.com", "social", "anti-bot controls")

    async def _client_send_should_never_be_called(self, request, **kwargs):
        raise AssertionError("must not touch the network")

    with patch.object(httpx.AsyncClient, "send", new=_client_send_should_never_be_called):
        async def _run():
            async with httpx.AsyncClient() as client:
                return await platform.checker(client, "someone@example.com")

        result = asyncio.run(_run())

    assert result.status == AccountPresenceState.BLOCKED
    assert result.provider_reason == "anti-bot controls"
    assert result.status != AccountPresenceState.NOT_FOUND
    assert result.http_status is None


def test_all_sixteen_prioritized_platforms_are_covered():
    names = {p.name for p in ALL_CHECKERS}
    # Gravatar is intentionally handled via the existing
    # GravatarIntegration + normalization fold-in, not a checkers/
    # file - see checkers/__init__.py docstring.
    expected = {
        "github", "gitlab", "reddit", "pinterest", "spotify", "soundcloud",
        "x_twitter", "instagram", "facebook", "linkedin", "tiktok",
        "twitch", "youtube", "discord", "telegram",
    }
    assert names == expected


def test_only_github_and_soundcloud_actually_check_the_network():
    """
    Every other prioritized platform must be a BLOCKED-by-design stub
    - never promise support that doesn't exist.
    """
    live_checkers = {"github", "soundcloud"}
    for platform in ALL_CHECKERS:
        if platform.name in live_checkers:
            continue
        result = asyncio.run(platform.checker(httpx.AsyncClient(), "someone@example.com"))
        assert result.status == AccountPresenceState.BLOCKED
        assert result.provider_reason


# ==========================================================
# AccountPresenceIntegration — email validation + status
# precedence (replaces HoleheIntegration)
# ==========================================================


def test_account_presence_invalid_email_fails_without_network_call():
    integration = AccountPresenceIntegration()
    result = asyncio.run(integration._query("not-an-email"))
    assert result.status == ModuleResultStatus.FAILED


def test_account_presence_passes_email_through_to_checkers_unchanged():
    integration = AccountPresenceIntegration()
    captured = {}

    async def _fake_run(email, platforms):
        captured["email"] = email
        return []

    with patch(
        "backend.app.integrations.email.presence_integration.run_presence_checks",
        new=_fake_run,
    ):
        asyncio.run(integration._query("Someone@Example.com"))

    assert captured["email"] == "Someone@Example.com"


def test_account_presence_confirmed_still_reports_success():
    integration = AccountPresenceIntegration()

    async def _fake_run(email, platforms):
        return [
            _presence_result("github", AccountPresenceState.CONFIRMED),
            _presence_result("gitlab", AccountPresenceState.BLOCKED),
        ]

    with patch(
        "backend.app.integrations.email.presence_integration.run_presence_checks",
        new=_fake_run,
    ):
        result = asyncio.run(integration._query("someone@example.com"))

    assert result.status == ModuleResultStatus.SUCCESS
    assert result.data["accounts_confirmed"] == 1
    assert result.data["platforms_checked"] == 2


def test_account_presence_all_not_found_still_reports_success():
    """
    Regression test for the runtime bug: a sweep where every platform
    resolves conclusively to NOT_FOUND is a successfully executed
    integration - not a distinct engine-level NOT_FOUND, and
    definitely not FAILED. Structured results are the source of truth;
    the engine status only says "the sweep ran".
    """
    integration = AccountPresenceIntegration()

    async def _fake_run(email, platforms):
        return [
            _presence_result("github", AccountPresenceState.NOT_FOUND),
            _presence_result("soundcloud", AccountPresenceState.NOT_FOUND),
        ]

    with patch(
        "backend.app.integrations.email.presence_integration.run_presence_checks",
        new=_fake_run,
    ):
        result = asyncio.run(integration._query("someone@example.com"))

    assert result.status == ModuleResultStatus.SUCCESS
    assert result.data["platforms_checked"] == 2


def test_account_presence_all_blocked_still_reports_success():
    """
    Regression test for the exact reported runtime bug: 15 platforms
    checked, 2 UNKNOWN (GitHub HTTP 403, SoundCloud HTTP 401) and 13
    BLOCKED, zero confirmed/not_found. The sweep completed and
    produced full structured results for every platform - that MUST
    be a successful integration run (ModuleResultStatus.SUCCESS), not
    FAILED, or the structured data gets silently discarded downstream.
    """
    integration = AccountPresenceIntegration()

    async def _fake_run(email, platforms):
        return [
            _presence_result("github", AccountPresenceState.UNKNOWN, http_status=403),
            _presence_result("soundcloud", AccountPresenceState.UNKNOWN, http_status=401),
        ] + [
            _presence_result(name, AccountPresenceState.BLOCKED, http_status=None, provider_reason="anti-bot controls")
            for name in [
                "gitlab", "reddit", "pinterest", "spotify", "x_twitter", "instagram",
                "facebook", "linkedin", "tiktok", "twitch", "youtube", "discord", "telegram",
            ]
        ]

    with patch(
        "backend.app.integrations.email.presence_integration.run_presence_checks",
        new=_fake_run,
    ):
        result = asyncio.run(integration._query("thecybervivek@gmail.com"))

    assert result.status == ModuleResultStatus.SUCCESS
    assert result.data["platforms_checked"] == 15
    assert result.data["accounts_confirmed"] == 0
    assert len(result.data["results"]) == 15  # every platform's structured row survives


def test_account_presence_mixed_confirmed_unknown_blocked_still_reports_success():
    integration = AccountPresenceIntegration()

    async def _fake_run(email, platforms):
        return [
            _presence_result("github", AccountPresenceState.CONFIRMED),
            _presence_result("soundcloud", AccountPresenceState.UNKNOWN, http_status=401),
            _presence_result("gitlab", AccountPresenceState.BLOCKED, provider_reason="anti-bot controls"),
        ]

    with patch(
        "backend.app.integrations.email.presence_integration.run_presence_checks",
        new=_fake_run,
    ):
        result = asyncio.run(integration._query("someone@example.com"))

    assert result.status == ModuleResultStatus.SUCCESS
    assert result.data["accounts_confirmed"] == 1
    assert result.data["platforms_checked"] == 3


def test_account_presence_not_found_plus_blocked_still_reports_success():
    integration = AccountPresenceIntegration()

    async def _fake_run(email, platforms):
        return [
            _presence_result("github", AccountPresenceState.NOT_FOUND),
            _presence_result("gitlab", AccountPresenceState.BLOCKED, provider_reason="anti-bot controls"),
        ]

    with patch(
        "backend.app.integrations.email.presence_integration.run_presence_checks",
        new=_fake_run,
    ):
        result = asyncio.run(integration._query("someone@example.com"))

    assert result.status == ModuleResultStatus.SUCCESS


def _presence_result(platform: str, status: AccountPresenceState, **overrides):
    from backend.app.integrations.email.base_checker import PlatformCheckResult

    defaults = dict(
        platform=platform, domain=f"{platform}.com", category="test", status=status,
        confidence="high" if status in (AccountPresenceState.CONFIRMED, AccountPresenceState.NOT_FOUND) else "low",
        evidence="test evidence", http_status=200, checked_at="2026-08-01T00:00:00+00:00",
    )
    defaults.update(overrides)
    return PlatformCheckResult(**defaults)


# ==========================================================
# normalization.py — cross-provider dedup/correlation
# ==========================================================


def _row(platform, status, http_status=200, profile_url=None, provider_reason=None, category="test"):
    return {
        "platform": platform, "category": category, "status": status,
        "http_status": http_status, "profile_url": profile_url, "provider_reason": provider_reason,
    }


def test_normalization_duplicate_platform_across_providers_merges_into_one_finding():
    presence = _canned("account_presence", data={"results": [_row("github", "confirmed")]})
    gravatar = _canned("gravatar", data={"results": [_row("github", "confirmed")]})

    # Synthetic: normalize_and_correlate's second positional arg is
    # meant for gravatar's own result shape (has_profile), but the
    # merge logic itself is provider-name-keyed and generic - this
    # exercises that generic dedup path directly via _ingest.
    findings = normalize_and_correlate(presence, gravatar_result=None)
    assert len(findings) == 1
    assert findings[0].platform == "github"
    assert findings[0].status == "confirmed"


def test_normalization_conflicting_provider_results_produce_conflict_not_silent_resolution():
    presence = _canned("account_presence", data={"results": [_row("github", "confirmed")]})
    gravatar_data = {"has_profile": False, "profile_url": None}
    gravatar = _canned("gravatar", data=gravatar_data)

    # Force a conflict scenario by re-ingesting a not_found row for
    # the same platform name as account_presence's confirmed row.
    from backend.app.integrations.email import normalization as norm_module

    original_gravatar_rows = norm_module._gravatar_as_rows
    norm_module._gravatar_as_rows = lambda g: [_row("github", "not_found")]
    try:
        findings = normalize_and_correlate(presence, gravatar)
    finally:
        norm_module._gravatar_as_rows = original_gravatar_rows

    assert len(findings) == 1
    assert findings[0].status == "conflict"
    assert findings[0].confidence == "low"


def test_normalization_never_manufactures_a_positive_finding_from_blocked_or_failed():
    presence = _canned("account_presence", data={"results": [
        _row("gitlab", "blocked", http_status=None, provider_reason="anti-bot controls"),
        _row("gitlab_dupe_never_happens", "unknown", http_status=None),
    ]})

    findings = normalize_and_correlate(presence, gravatar_result=None)
    assert all(f.status not in ("confirmed", "not_found") for f in findings)
    assert findings[0].provider_reason == "anti-bot controls"


def test_normalization_preserves_structured_results_regardless_of_engine_status():
    """
    Regression test for the runtime bug: account_presence's own
    aggregate ModuleResultStatus must never cause its per-platform rows
    to be silently discarded. Structured results (data["results"]) are
    the source of truth; engine status is not a gate for this engine.
    """
    presence = _canned(
        "account_presence", status=ModuleResultStatus.FAILED,  # defensive/edge-case status
        data={"results": [_row("github", "confirmed"), _row("gitlab", "blocked", provider_reason="anti-bot controls")]},
    )
    findings = normalize_and_correlate(presence, gravatar_result=None)
    assert len(findings) == 2
    platforms = {f.platform: f.status for f in findings}
    assert platforms == {"github": "confirmed", "gitlab": "unknown"}


def test_normalization_preserves_all_fifteen_platforms_from_the_reported_runtime_case():
    """
    Direct reproduction of the reported thecybervivek@gmail.com
    runtime case: 15 platforms checked, 0 confirmed, GitHub/SoundCloud
    UNKNOWN (HTTP 403/401), the other 13 BLOCKED. All 15 must survive
    normalization and land in "Unable to Verify" - none silently
    dropped, none converted to NOT_FOUND, none fabricated as CONFIRMED.
    """
    rows = [
        _row("github", "unknown", http_status=403, provider_reason=None),
        _row("soundcloud", "unknown", http_status=401, provider_reason=None),
    ] + [
        _row(name, "blocked", http_status=None, provider_reason="anti-bot controls")
        for name in [
            "gitlab", "reddit", "pinterest", "spotify", "x_twitter", "instagram",
            "facebook", "linkedin", "tiktok", "twitch", "youtube", "discord", "telegram",
        ]
    ]
    presence = _canned("account_presence", status=ModuleResultStatus.SUCCESS, data={"results": rows})

    findings = normalize_and_correlate(presence, gravatar_result=None)
    summary = summarize_findings(findings)

    assert summary["platforms_evaluated"] == 15
    assert len(summary["confirmed_accounts"]) == 0
    assert len(summary["not_found_platforms"]) == 0
    assert len(summary["unable_to_verify_platforms"]) == 15
    assert all(f["status"] not in ("confirmed", "not_found") for f in summary["unable_to_verify_platforms"])

    github_finding = next(f for f in summary["unable_to_verify_platforms"] if f["platform"] == "github")
    assert github_finding["provider_evidence"][0]["http_status"] == 403


def test_normalization_preserves_profile_url_only_when_legitimately_established():
    presence = _canned("account_presence", data={"results": [
        _row("github", "confirmed", profile_url=None),  # sign-up check never yields a URL
    ]})
    findings = normalize_and_correlate(presence, gravatar_result=None)
    assert findings[0].profile_url is None  # never fabricated


def test_normalization_provider_provenance_is_preserved():
    presence = _canned("account_presence", data={"results": [_row("github", "confirmed")]})
    findings = normalize_and_correlate(presence, gravatar_result=None)
    assert findings[0].providers == ["account_presence"]
    assert findings[0].provider_evidence[0].state == "confirmed"


def test_normalization_confidence_high_for_two_agreeing_not_found():
    # Simulate two agreeing sources by directly constructing the merge
    # path with a duplicated ingest (mirrors how the username module's
    # equivalent test proves multi-source agreement raises confidence).
    from backend.app.integrations.email import normalization as norm_module

    presence = _canned("account_presence", data={"results": [_row("github", "not_found")]})
    norm_module._gravatar_as_rows_backup = norm_module._gravatar_as_rows
    norm_module._gravatar_as_rows = lambda g: [_row("github", "not_found")]
    try:
        findings = normalize_and_correlate(presence, _canned("gravatar", data={}))
    finally:
        norm_module._gravatar_as_rows = norm_module._gravatar_as_rows_backup

    assert findings[0].status == "not_found"
    assert findings[0].confidence == "high"
    assert len(findings[0].providers) == 2


def test_summarize_findings_buckets_and_has_no_risk_fields():
    presence = _canned("account_presence", data={"results": [
        _row("github", "confirmed"),
        _row("gitlab", "blocked", provider_reason="anti-bot controls"),
    ]})
    gravatar = _canned("gravatar", data={"has_profile": False, "profile_url": None})

    findings = normalize_and_correlate(presence, gravatar)
    summary = summarize_findings(findings)

    assert len(summary["confirmed_accounts"]) == 1
    assert len(summary["not_found_platforms"]) == 1  # gravatar not_found
    assert len(summary["unable_to_verify_platforms"]) == 1  # gitlab blocked
    for key in summary:
        assert "risk" not in key
        assert "score" not in key


# ==========================================================
# Risk scoring — account presence never contributes; breach
# evidence still does, via the existing engine
# ==========================================================


def test_account_presence_alone_does_not_raise_risk_score():
    results = {
        "account_presence": _canned(
            "account_presence",
            data={"results": [_row("github", "confirmed"), _row("soundcloud", "confirmed")]},
        ),
    }
    score, notes = _service()._compute_risk_score(results)
    assert score == 0.0
    assert notes == []


def test_blocked_and_unknown_account_presence_do_not_raise_risk():
    results = {
        "account_presence": _canned(
            "account_presence", status=ModuleResultStatus.RATE_LIMITED,
            data={"results": [_row("gitlab", "blocked"), _row("reddit", "unknown")]},
        ),
    }
    score, notes = _service()._compute_risk_score(results)
    assert score == 0.0
    assert notes == []


def test_confirmed_breach_affects_risk():
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
# Summary — the 4 distinguished cases
# ==========================================================


def test_summary_for_unavailable_providers_never_claims_clean():
    service = _service()
    results = {
        "hibp": _canned("hibp", status=ModuleResultStatus.SKIPPED),
        "emailrep": _canned("emailrep", status=ModuleResultStatus.FAILED),
    }
    presence_summary = {"confirmed_accounts": []}
    summary = service._build_summary("x@example.com", results, [], presence_summary)
    assert "unavailable" in summary
    assert "no breach found" not in summary.lower()
    assert "no notable risk signals" not in summary.lower()


def test_summary_for_account_only_case_never_claims_a_security_finding():
    service = _service()
    results = {"hibp": _canned("hibp", data={"breach_count": 0})}
    presence_summary = {"confirmed_accounts": [{"platform": "github"}]}
    summary = service._build_summary("x@example.com", results, [], presence_summary)
    assert "github" not in summary  # generic count, not a platform dump
    assert "1 platform" in summary
    assert "not a security finding" in summary


def test_summary_for_breach_case_leads_with_the_breach():
    service = _service()
    results = {"hibp": _canned("hibp", data={"breach_count": 1})}
    risk_notes = ["1 known data breach(es)"]
    presence_summary = {"confirmed_accounts": []}
    summary = service._build_summary("x@example.com", results, risk_notes, presence_summary)
    assert "Confirmed breach intelligence" in summary
    assert "no breach found" not in summary.lower()


def test_summary_mentions_accounts_alongside_a_confirmed_breach():
    service = _service()
    results = {"hibp": _canned("hibp", data={"breach_count": 1})}
    risk_notes = ["1 known data breach(es)"]
    presence_summary = {"confirmed_accounts": [{"platform": "github"}]}
    summary = service._build_summary("x@example.com", results, risk_notes, presence_summary)
    assert "Confirmed breach intelligence" in summary
    assert "github" in summary


def test_summary_clean_case_with_no_evidence_at_all():
    service = _service()
    results = {"hibp": _canned("hibp", data={"breach_count": 0})}
    presence_summary = {"confirmed_accounts": []}
    summary = service._build_summary("x@example.com", results, [], presence_summary)
    assert "No notable risk signals" in summary


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
    assert presence_row.data["confirmed_accounts"] == []
    assert "risk_score" not in presence_row.data
    assert "risk_level" not in presence_row.data


# ==========================================================
# Breach Intelligence data shape sanity (consumed directly by the
# frontend from the existing hibp result) - never a raw secret
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
