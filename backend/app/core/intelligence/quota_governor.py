"""
Quota governance (Section 6).

Tracks outbound calls per provider so a paid/free-tier API's daily
quota isn't blown through by repeated investigations. In-memory today
(single-process), with the same "swap the backend later without
changing call sites" seam already established for rate limiting in
core/rate_limit.py - a production deployment would back this with
Redis/a real counter store; nothing here hard-codes a real provider's
actual quota or any API credential, since neither is knowable/safe to
assume generically.

Soft threshold: a warning state - callers SHOULD prefer cache and skip
strictly-optional enrichment, but the call can still proceed.
Hard threshold: the call MUST be blocked and the provider's evidence
reported as EvidenceState.QUOTA_EXHAUSTED - never NOT_FOUND, never a
generic FAILED (that would misrepresent "we chose not to ask" as
either "we asked and found nothing" or "something broke").
"""

from dataclasses import dataclass
from dataclasses import field
from datetime import date


@dataclass
class ProviderQuotaPolicy:

    provider: str
    daily_limit: int
    soft_threshold_ratio: float = 0.8  # warn once 80% of daily_limit is used
    quota_remaining_known: int | None = None  # set if the provider's own API reports it


@dataclass
class ProviderQuotaState:

    provider: str
    date_key: str
    calls_today: int = 0
    successful_calls: int = 0
    failed_calls: int = 0
    cache_hits: int = 0
    rate_limited_calls: int = 0

    def to_dict(self) -> dict:

        return {
            "provider": self.provider,
            "date": self.date_key,
            "calls_today": self.calls_today,
            "successful_calls": self.successful_calls,
            "failed_calls": self.failed_calls,
            "cache_hits": self.cache_hits,
            "rate_limited_calls": self.rate_limited_calls,
        }


class QuotaDecision:

    ALLOW = "allow"
    ALLOW_SOFT_WARNING = "allow_soft_warning"
    BLOCK_HARD_LIMIT = "block_hard_limit"


class QuotaGovernor:
    """
    In-memory quota tracker keyed by (provider, day). Not thread/process
    -safe beyond a single asyncio event loop, matching this project's
    existing in-memory rate limiter's stated scope - see its docstring
    for the intended Redis upgrade path.
    """

    def __init__(self) -> None:
        self._policies: dict[str, ProviderQuotaPolicy] = {}
        self._state: dict[tuple[str, str], ProviderQuotaState] = {}

    def register_policy(self, policy: ProviderQuotaPolicy) -> None:
        self._policies[policy.provider] = policy

    def _today_key(self) -> str:
        return date.today().isoformat()

    def _state_for(self, provider: str) -> ProviderQuotaState:

        key = (provider, self._today_key())

        if key not in self._state:
            self._state[key] = ProviderQuotaState(provider=provider, date_key=key[1])

        return self._state[key]

    def check(self, provider: str) -> str:
        """
        Returns a QuotaDecision WITHOUT recording a call - call this
        before making the request, then call record_result() after.
        A provider with no registered policy is always ALLOW (quota
        governance is opt-in per provider, not assumed).
        """

        policy = self._policies.get(provider)

        if policy is None:
            return QuotaDecision.ALLOW

        state = self._state_for(provider)

        if state.calls_today >= policy.daily_limit:
            return QuotaDecision.BLOCK_HARD_LIMIT

        if state.calls_today >= policy.daily_limit * policy.soft_threshold_ratio:
            return QuotaDecision.ALLOW_SOFT_WARNING

        return QuotaDecision.ALLOW

    def record_result(
        self,
        provider: str,
        *,
        success: bool | None = None,
        cache_hit: bool = False,
        rate_limited: bool = False,
    ) -> None:

        state = self._state_for(provider)

        if cache_hit:
            state.cache_hits += 1
            return  # a cache hit doesn't consume provider quota

        state.calls_today += 1

        if rate_limited:
            state.rate_limited_calls += 1
        elif success:
            state.successful_calls += 1
        elif success is False:
            state.failed_calls += 1

    def get_state(self, provider: str) -> ProviderQuotaState:
        return self._state_for(provider)

    def remaining(self, provider: str) -> int | None:

        policy = self._policies.get(provider)

        if policy is None:
            return None

        state = self._state_for(provider)

        return max(0, policy.daily_limit - state.calls_today)
