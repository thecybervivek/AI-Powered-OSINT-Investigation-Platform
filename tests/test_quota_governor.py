from backend.app.core.intelligence.quota_governor import ProviderQuotaPolicy
from backend.app.core.intelligence.quota_governor import QuotaDecision
from backend.app.core.intelligence.quota_governor import QuotaGovernor


def test_unregistered_provider_always_allowed():

    gov = QuotaGovernor()

    assert gov.check("unregistered_provider") == QuotaDecision.ALLOW


def test_soft_threshold_warning():

    gov = QuotaGovernor()
    gov.register_policy(ProviderQuotaPolicy(provider="shodan", daily_limit=10, soft_threshold_ratio=0.8))

    for _ in range(7):
        assert gov.check("shodan") == QuotaDecision.ALLOW
        gov.record_result("shodan", success=True)

    assert gov.get_state("shodan").calls_today == 7
    assert gov.check("shodan") == QuotaDecision.ALLOW  # 7 < 8 (80% of 10)

    gov.record_result("shodan", success=True)  # 8th call
    assert gov.check("shodan") == QuotaDecision.ALLOW_SOFT_WARNING


def test_hard_threshold_blocks():

    gov = QuotaGovernor()
    gov.register_policy(ProviderQuotaPolicy(provider="shodan", daily_limit=10))

    for _ in range(10):
        gov.record_result("shodan", success=True)

    assert gov.get_state("shodan").calls_today == 10
    assert gov.check("shodan") == QuotaDecision.BLOCK_HARD_LIMIT


def test_remaining_reports_zero_at_hard_limit_and_none_for_unregistered():

    gov = QuotaGovernor()
    gov.register_policy(ProviderQuotaPolicy(provider="shodan", daily_limit=1))
    gov.record_result("shodan", success=True)

    assert gov.remaining("shodan") == 0
    assert gov.remaining("unregistered") is None


def test_cache_hits_never_consume_quota():

    gov = QuotaGovernor()
    gov.register_policy(ProviderQuotaPolicy(provider="vt", daily_limit=1))

    gov.record_result("vt", cache_hit=True)
    gov.record_result("vt", cache_hit=True)
    gov.record_result("vt", cache_hit=True)

    assert gov.check("vt") == QuotaDecision.ALLOW
    assert gov.get_state("vt").cache_hits == 3
    assert gov.get_state("vt").calls_today == 0
