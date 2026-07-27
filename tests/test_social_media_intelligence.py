import pytest

from backend.app.integrations.username.base_checker import PlatformCheckResult
from backend.app.integrations.username.platforms import social_media_platforms
from backend.app.services.social_media_service import SocialMediaIntelligenceService


# ==========================================================
# Platform catalogue - exactly the 8 platforms this milestone requires
# ==========================================================

_EXPECTED_PLATFORMS = {
    "GitHub",
    "LinkedIn",
    "X (Twitter)",
    "Instagram",
    "Facebook",
    "Reddit",
    "Medium",
    "HackerOne",
}


def test_social_media_platforms_matches_milestone_spec():

    platforms = social_media_platforms()
    names = {p.name for p in platforms}

    assert names == _EXPECTED_PLATFORMS
    assert len(platforms) == len(_EXPECTED_PLATFORMS)  # no duplicates


def test_social_media_platforms_are_all_public_profile_urls():
    """
    Every entry must be a plain public profile URL template (no API
    keys/auth params baked in) - this module only ever checks public
    pages, consistent with the ToS/scraping boundary agreed for this
    milestone.
    """

    for platform in social_media_platforms():

        assert platform.url_template.startswith("https://")
        assert "{}" in platform.url_template
        assert "key=" not in platform.url_template.lower()
        assert "token=" not in platform.url_template.lower()


# ==========================================================
# SocialMediaIntelligenceService - pure logic (no DB, no network)
# ==========================================================

def _service() -> SocialMediaIntelligenceService:
    return SocialMediaIntelligenceService(db=None)


def _check(platform: str, exists: bool | None, category: str = "social") -> PlatformCheckResult:

    return PlatformCheckResult(
        platform=platform,
        category=category,
        exists=exists,
        profile_url=f"https://example.test/{platform}",
        http_status=200 if exists else 404,
        latency_ms=10,
        error=None,
    )


def test_build_profile_discovery_counts_confirmed_platforms():

    service = _service()

    checks = [
        _check("GitHub", True),
        _check("Reddit", True),
        _check("Facebook", False),
        _check("Medium", None),
    ]

    data = service._build_profile_discovery("alice", checks)

    assert data["username"] == "alice"
    assert data["platforms_checked"] == 4
    assert data["confirmed_count"] == 2
    assert data["confirmed_platforms"] == ["GitHub", "Reddit"]
    assert len(data["results"]) == 4


def test_build_correlation_reports_platform_overlap():

    service = _service()

    related_checks = {
        "alice_dev": [_check("GitHub", True), _check("Reddit", False)],
        "alice2024": [_check("GitHub", False), _check("Instagram", True)],
    }

    correlation = service._build_correlation(
        primary_username="alice",
        primary_confirmed_platforms=["GitHub", "Reddit"],
        related_checks_by_name=related_checks,
    )

    by_username = {c["username"]: c for c in correlation["correlations"]}

    assert correlation["related_usernames_checked"] == 2
    assert by_username["alice_dev"]["overlapping_platforms_with_primary"] == ["GitHub"]
    assert by_username["alice_dev"]["overlap_count"] == 1
    assert by_username["alice2024"]["overlapping_platforms_with_primary"] == []
    assert by_username["alice2024"]["overlap_count"] == 0


def test_risk_score_zero_when_no_platforms_confirmed():

    service = _service()

    discovery_data = {
        "confirmed_count": 0,
        "confirmed_platforms": [],
        "platforms_checked": 8,
    }

    score, notes = service._compute_risk_score(discovery_data, {})

    assert score == 0.0
    assert notes == []


def test_risk_score_increases_with_confirmed_platform_count():

    service = _service()

    low = service._compute_risk_score(
        {"confirmed_count": 1, "confirmed_platforms": ["GitHub"], "platforms_checked": 8},
        {},
    )
    high = service._compute_risk_score(
        {
            "confirmed_count": 5,
            "confirmed_platforms": ["GitHub", "Reddit", "Medium", "LinkedIn", "Facebook"],
            "platforms_checked": 8,
        },
        {},
    )

    assert high[0] > low[0]


def test_risk_score_flags_alias_overlap():

    service = _service()

    discovery_data = {
        "confirmed_count": 1,
        "confirmed_platforms": ["GitHub"],
        "platforms_checked": 8,
    }

    related_checks = {
        "alice_dev": [_check("GitHub", True)],
    }

    score, notes = service._compute_risk_score(discovery_data, related_checks)

    assert score > 0
    assert any("alias correlation" in note.lower() for note in notes)


def test_build_summary_reports_no_findings():

    service = _service()

    summary = service._build_summary(
        "alice",
        {"confirmed_count": 0, "confirmed_platforms": [], "platforms_checked": 8},
        risk_notes=[],
    )

    assert "No public profiles found" in summary
    assert "alice" in summary


def test_build_summary_joins_risk_notes():

    service = _service()

    summary = service._build_summary(
        "alice",
        {"confirmed_count": 1, "confirmed_platforms": ["GitHub"], "platforms_checked": 8},
        risk_notes=["Confirmed public profile on 1 of 8 tracked platforms"],
    )

    assert "Confirmed public profile on 1 of 8" in summary
    assert "alice" in summary
