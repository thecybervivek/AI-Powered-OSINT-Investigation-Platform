"""
Standalone Username Intelligence test suite.

Deliberately self-contained (does not use tests/conftest.py's
TestClient/Alembic fixtures) so it can run against just this backup's
backend/app + an in-memory SQLite database, with no migrations
directory required. Covers:

  - base_checker._evaluate_existence HTTP-status semantics, including
    the exact false-positive scenario reported for X/Twitter,
    Snapchat, VKontakte, and Gravatar (404 body without the expected
    "missing" marker text).
  - normalize_and_correlate / summarize_findings cross-engine
    deduplication and conflict handling.
  - UsernameIntelligenceService end-to-end: no risk_score/risk_level
    is ever produced, regardless of how many profiles are confirmed.
"""

import asyncio
import os
import sys
import uuid
from pathlib import Path

os.environ.setdefault("DATABASE_URL", "sqlite:///./test_username_standalone.db")
os.environ.setdefault("ENVIRONMENT", "testing")

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import httpx
import pytest

from backend.app.integrations.base import IntegrationResult
from backend.app.integrations.username.base_checker import _evaluate_existence
from backend.app.integrations.username.normalization import normalize_and_correlate
from backend.app.integrations.username.normalization import summarize_findings
from backend.app.integrations.username.platforms import DetectionMethod
from backend.app.integrations.username.platforms import PlatformDefinition
from backend.app.models.investigation import ModuleResultStatus


def _response(status_code: int, text: str = "") -> httpx.Response:
    return httpx.Response(
        status_code=status_code,
        text=text,
        request=httpx.Request("GET", "https://example.com/testuser"),
    )


# ==========================================================
# HTTP-status semantics (base_checker._evaluate_existence)
# ==========================================================

STATUS_CODE_PLATFORM = PlatformDefinition(
    "GitHub", "development", "https://github.com/{}", DetectionMethod.STATUS_CODE,
)

# Mirrors the real X (Twitter) platform definition that produced the
# reported false positive: ERROR_STRING_IN_BODY, existing_status=200.
ERROR_STRING_PLATFORM = PlatformDefinition(
    "X (Twitter)", "social", "https://x.com/{}",
    DetectionMethod.ERROR_STRING_IN_BODY, "This account doesn\u2019t exist",
)

REDIRECT_PLATFORM = PlatformDefinition(
    "Reddit", "social", "https://www.reddit.com/user/{}/about.json",
    DetectionMethod.REDIRECT_ON_MISSING,
)


def test_status_code_200_confirms():
    assert _evaluate_existence(STATUS_CODE_PLATFORM, _response(200)) is True


def test_status_code_404_is_not_found():
    assert _evaluate_existence(STATUS_CODE_PLATFORM, _response(404)) is False


def test_status_code_403_is_unknown():
    assert _evaluate_existence(STATUS_CODE_PLATFORM, _response(403)) is None


def test_status_code_999_is_unknown():
    assert _evaluate_existence(STATUS_CODE_PLATFORM, _response(999)) is None


def test_status_code_500_is_unknown():
    assert _evaluate_existence(STATUS_CODE_PLATFORM, _response(500)) is None


def test_status_code_unexpected_status_is_unknown_not_confirmed():
    """A constructed URL that returns some other status (e.g. a 301
    the STATUS_CODE method doesn't recognize) must never be silently
    treated as confirmed."""
    assert _evaluate_existence(STATUS_CODE_PLATFORM, _response(301)) is None


def test_error_string_200_without_marker_confirms():
    assert _evaluate_existence(ERROR_STRING_PLATFORM, _response(200, "Welcome to the profile")) is True


def test_error_string_200_with_marker_is_not_found():
    assert _evaluate_existence(
        ERROR_STRING_PLATFORM, _response(200, "This account doesn\u2019t exist"),
    ) is False


def test_error_string_404_is_not_found_even_without_marker_text():
    """
    THE REPORTED FALSE-POSITIVE BUG: a 404 response whose body is a
    generic error page (no literal "This account doesn't exist" text)
    used to be misread as exists=True because the old implementation
    never looked at the status code for ERROR_STRING_IN_BODY
    platforms. Must now be NOT_FOUND.
    """
    generic_404_body = "<html><body>404 - Page not found</body></html>"
    assert _evaluate_existence(ERROR_STRING_PLATFORM, _response(404, generic_404_body)) is False


def test_error_string_403_is_unknown_never_not_found():
    assert _evaluate_existence(ERROR_STRING_PLATFORM, _response(403, "Access Denied")) is None


def test_error_string_999_is_unknown():
    assert _evaluate_existence(ERROR_STRING_PLATFORM, _response(999)) is None


def test_redirect_on_missing_404_is_not_found():
    assert _evaluate_existence(REDIRECT_PLATFORM, _response(404)) is False


def test_redirect_on_missing_3xx_is_not_found():
    assert _evaluate_existence(REDIRECT_PLATFORM, _response(302)) is False


def test_redirect_on_missing_200_confirms():
    assert _evaluate_existence(REDIRECT_PLATFORM, _response(200)) is True


def test_redirect_on_missing_403_is_unknown():
    assert _evaluate_existence(REDIRECT_PLATFORM, _response(403)) is None


# ==========================================================
# Normalization / cross-engine deduplication
# ==========================================================

def _engine_result(source: str, status: ModuleResultStatus, rows: list[dict]) -> IntegrationResult:
    return IntegrationResult(
        source=source,
        status=status,
        data={"username": "thecybervivek", "results": rows},
    )


def _row(platform, exists, http_status=200, error=None, profile_url=None, category="development"):
    return {
        "platform": platform,
        "category": category,
        "exists": exists,
        "profile_url": profile_url or f"https://example.com/{platform}",
        "http_status": http_status,
        "latency_ms": 50,
        "error": error,
    }


def test_agreement_across_all_three_engines_yields_one_canonical_finding():
    engine_results = [
        _engine_result("sherlock", ModuleResultStatus.SUCCESS, [_row("GitHub", True)]),
        _engine_result("maigret", ModuleResultStatus.SUCCESS, [_row("GitHub", True)]),
        _engine_result("whatsmyname", ModuleResultStatus.SUCCESS, [_row("GitHub", True)]),
    ]

    findings = normalize_and_correlate(engine_results)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.platform == "GitHub"
    assert finding.status == "confirmed"
    assert finding.confidence == "high"
    assert sorted(finding.providers) == ["maigret", "sherlock", "whatsmyname"]


def test_agreement_across_two_engines_yields_one_canonical_finding():
    engine_results = [
        _engine_result("sherlock", ModuleResultStatus.SUCCESS, [_row("GitHub", True)]),
        _engine_result("maigret", ModuleResultStatus.SUCCESS, [_row("GitHub", True)]),
    ]

    findings = normalize_and_correlate(engine_results)

    assert len(findings) == 1
    assert findings[0].status == "confirmed"
    assert sorted(findings[0].providers) == ["maigret", "sherlock"]


def test_provider_disagreement_is_conflict_not_silently_resolved():
    engine_results = [
        _engine_result("sherlock", ModuleResultStatus.NOT_FOUND, [_row("GitHub", False, http_status=404)]),
        _engine_result("maigret", ModuleResultStatus.SUCCESS, [_row("GitHub", True, http_status=200)]),
    ]

    findings = normalize_and_correlate(engine_results)

    assert len(findings) == 1
    assert findings[0].status == "conflict"


def test_skipped_provider_is_not_counted_as_checked():
    engine_results = [
        _engine_result("sherlock", ModuleResultStatus.SKIPPED, [_row("GitHub", True)]),
    ]

    findings = normalize_and_correlate(engine_results)

    assert findings == []


def test_failed_provider_is_not_converted_into_not_found():
    engine_results = [
        _engine_result("sherlock", ModuleResultStatus.FAILED, [_row("GitHub", False, http_status=404)]),
    ]

    findings = normalize_and_correlate(engine_results)

    # FAILED engines contribute nothing - GitHub must not appear at
    # all, and certainly not as a not_found finding.
    assert findings == []


def test_rate_limited_provider_is_not_converted_into_not_found():
    engine_results = [
        _engine_result("maigret", ModuleResultStatus.RATE_LIMITED, [_row("GitHub", False, http_status=404)]),
    ]

    findings = normalize_and_correlate(engine_results)

    assert findings == []


def test_inconclusive_rows_yield_unknown_status():
    engine_results = [
        _engine_result(
            "sherlock", ModuleResultStatus.NOT_FOUND,
            [_row("GitHub", None, http_status=None, error="Network error: ConnectError")],
        ),
    ]

    findings = normalize_and_correlate(engine_results)

    assert len(findings) == 1
    assert findings[0].status == "unknown"


def test_summarize_findings_has_no_risk_fields():
    engine_results = [
        _engine_result("sherlock", ModuleResultStatus.SUCCESS, [
            _row("GitHub", True), _row("GitLab", True), _row("Bitbucket", True),
        ]),
        _engine_result("maigret", ModuleResultStatus.SUCCESS, [
            _row("GitHub", True), _row("Instagram", True),
        ]),
        _engine_result("whatsmyname", ModuleResultStatus.SUCCESS, [
            _row("GitHub", True), _row("Replit", True), _row("PyPI", True), _row("Twitch", True),
        ]),
    ]

    findings = normalize_and_correlate(engine_results)
    summary = summarize_findings(findings)

    # 11 confirmed platform mentions total, deduplicated down to
    # fewer canonical findings - and NO risk/score/level key anywhere.
    assert len(summary["confirmed_profiles"]) >= 1
    for key in summary:
        assert "risk" not in key
        assert "score" not in key


# ==========================================================
# End-to-end service test (mocked engines - no live network calls)
# ==========================================================

@pytest.fixture()
def db_session():
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from backend.app.db.database import Base

    engine = create_engine(
        f"sqlite:///./test_username_standalone_{uuid.uuid4().hex}.db",
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(bind=engine)
    SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


def _make_user(session):
    from backend.app.models.user import User
    from backend.app.core.security import hash_password

    user = User(
        full_name="Test User",
        username=f"tester-{uuid.uuid4().hex[:8]}",
        email=f"tester-{uuid.uuid4().hex[:8]}@example.com",
        hashed_password=hash_password("Sup3rSecret!"),
    )
    session.add(user)
    session.commit()
    session.refresh(user)
    return user


def test_service_never_produces_risk_score_even_with_many_confirmed_profiles(db_session, monkeypatch):
    """
    Reproduces the reported bug scenario end-to-end: many platforms
    confirmed across multiple engines (previously -> risk_score=100 /
    Critical). Must now be risk_score=None / risk_level=None.
    """
    from backend.app.services import username_service as svc_module

    user = _make_user(db_session)

    class _FakeEngine:
        def __init__(self, source, status, rows):
            self.source_name = source
            self._status = status
            self._rows = rows

        async def run(self, target):
            return IntegrationResult(
                source=self.source_name,
                status=self._status,
                data={"username": target, "results": self._rows},
            )

    many_confirmed_rows = [_row(name, True) for name in
                            ["GitHub", "GitLab", "Bitbucket", "StackOverflow", "Dev.to",
                             "Replit", "Docker Hub", "npm", "PyPI", "Kaggle", "Instagram"]]

    fake_engines = [
        _FakeEngine("sherlock", ModuleResultStatus.SUCCESS, many_confirmed_rows[:6]),
        _FakeEngine("maigret", ModuleResultStatus.SUCCESS, many_confirmed_rows[6:9]),
        _FakeEngine("whatsmyname", ModuleResultStatus.SUCCESS, many_confirmed_rows[9:]),
    ]

    monkeypatch.setattr(svc_module, "_ENGINES", fake_engines)

    service = svc_module.UsernameIntelligenceService(db_session)

    investigation = asyncio.run(
        service.investigate(user_id=user.id, username="thecybervivek")
    )

    assert investigation.risk_score is None
    assert investigation.risk_level is None
    assert "Risk Score" not in (investigation.summary or "")
    assert "Critical" not in (investigation.summary or "")

    normalization_row = next(
        r for r in investigation.results if r.source == "username_normalization"
    )
    assert len(normalization_row.data["confirmed_profiles"]) == 11
    assert "risk_score" not in normalization_row.data
    assert "risk_level" not in normalization_row.data


def test_service_reflects_false_positive_fix_for_reported_platforms(db_session, monkeypatch):
    """
    Reproduces the exact platforms named in the bug report (X/Twitter,
    Snapchat, VKontakte, Gravatar) returning 404 with a generic body -
    confirms the service-level result now reports them as not_found,
    not confirmed.
    """
    from backend.app.services import username_service as svc_module
    from backend.app.integrations.username.base_checker import check_single_platform
    from backend.app.integrations.username.platforms import PLATFORM_CATALOGUE

    user = _make_user(db_session)

    reported_platforms = {"X (Twitter)", "Snapchat", "VKontakte", "Gravatar"}
    target_defs = [p for p in PLATFORM_CATALOGUE if p.name in reported_platforms]
    assert len(target_defs) == 4

    rows = []
    for platform in target_defs:
        response = _response(404, "<html>404 not found</html>")
        exists = _evaluate_existence(platform, response)
        rows.append(_row(platform.name, exists, http_status=404, category=platform.category))

    class _FakeEngine:
        source_name = "sherlock"

        async def run(self, target):
            return IntegrationResult(
                source="sherlock",
                status=ModuleResultStatus.NOT_FOUND,
                data={"username": target, "results": rows},
            )

    monkeypatch.setattr(svc_module, "_ENGINES", [_FakeEngine()])

    service = svc_module.UsernameIntelligenceService(db_session)
    investigation = asyncio.run(
        service.investigate(user_id=user.id, username="thecybervivek")
    )

    normalization_row = next(
        r for r in investigation.results if r.source == "username_normalization"
    )
    confirmed_names = {f["platform"] for f in normalization_row.data["confirmed_profiles"]}
    not_found_names = {f["platform"] for f in normalization_row.data["not_found_platforms"]}

    assert confirmed_names.isdisjoint(reported_platforms)
    assert reported_platforms.issubset(not_found_names)
    assert investigation.risk_score is None
