"""
Provider execution governance (Section 5).

Wraps any async provider call with: a timeout budget (a slow provider
must not indefinitely block an investigation), a concurrency limit
(shared across however many calls go through one ProviderRunner
instance), a circuit breaker per provider (a repeatedly failing
provider stops being hammered), quota governance (soft/hard thresholds
- see quota_governor.py), and simple TTL caching for repeated lookups
of the same unchanged indicator.

Deliberately designed as something existing services CAN adopt
incrementally (wrap one `integration.run(target)` call at a time)
rather than a rewrite of AsyncBaseIntegration itself - see the
integration notes in the delivery summary for why, and for the
suggested adoption path.
"""

import asyncio
import time
from dataclasses import dataclass
from dataclasses import field
from enum import Enum
from typing import Any
from typing import Awaitable
from typing import Callable

from backend.app.core.intelligence.circuit_breaker import CircuitBreaker
from backend.app.core.intelligence.circuit_breaker import CircuitBreakerConfig
from backend.app.core.intelligence.quota_governor import ProviderQuotaPolicy
from backend.app.core.intelligence.quota_governor import QuotaDecision
from backend.app.core.intelligence.quota_governor import QuotaGovernor


class ProviderExecutionState(str, Enum):

    SUCCESS = "success"
    TIMEOUT = "timeout"
    ERROR = "error"
    CIRCUIT_OPEN = "circuit_open"
    QUOTA_EXHAUSTED = "quota_exhausted"
    CACHE_HIT = "cache_hit"


@dataclass(frozen=True)
class ProviderExecutionResult:

    provider: str
    state: ProviderExecutionState
    value: Any = None
    error: str | None = None
    latency_ms: int = 0
    from_cache: bool = False

    def to_dict(self) -> dict:

        return {
            "provider": self.provider,
            "state": self.state.value,
            "error": self.error,
            "latency_ms": self.latency_ms,
            "from_cache": self.from_cache,
        }


@dataclass
class ProviderExecutionPolicy:

    timeout_seconds: float = 10.0
    max_concurrency: int = 10
    cache_ttl_seconds: float = 0.0  # 0 disables caching
    circuit_breaker_config: CircuitBreakerConfig = field(default_factory=CircuitBreakerConfig)


class ProviderRunner:
    """
    One instance is meant to be shared across the concurrent provider
    calls of a single investigation (or reused across the app - it's
    stateless enough to be either). `clock` is injectable for
    deterministic cache-expiry tests.
    """

    def __init__(
        self,
        policy: ProviderExecutionPolicy | None = None,
        quota_governor: QuotaGovernor | None = None,
        clock: Callable[[], float] | None = None,
    ) -> None:

        self._policy = policy or ProviderExecutionPolicy()
        self._quota_governor = quota_governor or QuotaGovernor()
        self._clock = clock or time.monotonic
        self._semaphore = asyncio.Semaphore(self._policy.max_concurrency)
        self._breakers: dict[str, CircuitBreaker] = {}
        self._cache: dict[tuple[str, str], tuple[Any, float]] = {}

    def register_quota_policy(self, policy: ProviderQuotaPolicy) -> None:
        self._quota_governor.register_policy(policy)

    def _breaker_for(self, provider: str) -> CircuitBreaker:

        if provider not in self._breakers:
            self._breakers[provider] = CircuitBreaker(
                self._policy.circuit_breaker_config, clock=self._clock,
            )

        return self._breakers[provider]

    def _cache_get(self, provider: str, key: str) -> Any:

        if self._policy.cache_ttl_seconds <= 0:
            return None

        entry = self._cache.get((provider, key))

        if entry is None:
            return None

        value, expires_at = entry

        if self._clock() >= expires_at:
            del self._cache[(provider, key)]
            return None

        return value

    def _cache_set(self, provider: str, key: str, value: Any) -> None:

        if self._policy.cache_ttl_seconds <= 0:
            return

        self._cache[(provider, key)] = (value, self._clock() + self._policy.cache_ttl_seconds)

    async def run(
        self,
        provider: str,
        cache_key: str,
        call: Callable[[], Awaitable[Any]],
    ) -> ProviderExecutionResult:
        """
        `call` is a zero-arg async callable (e.g. `lambda:
        integration.run(target)`) so this function controls exactly
        when it executes (after all the gating checks below).
        """

        cached = self._cache_get(provider, cache_key)

        if cached is not None:
            self._quota_governor.record_result(provider, cache_hit=True)
            return ProviderExecutionResult(
                provider=provider, state=ProviderExecutionState.CACHE_HIT,
                value=cached, from_cache=True,
            )

        breaker = self._breaker_for(provider)

        if not breaker.allow_request():
            return ProviderExecutionResult(provider=provider, state=ProviderExecutionState.CIRCUIT_OPEN)

        quota_decision = self._quota_governor.check(provider)

        if quota_decision == QuotaDecision.BLOCK_HARD_LIMIT:
            return ProviderExecutionResult(provider=provider, state=ProviderExecutionState.QUOTA_EXHAUSTED)

        start = self._clock()

        async with self._semaphore:

            try:
                value = await asyncio.wait_for(call(), timeout=self._policy.timeout_seconds)

            except asyncio.TimeoutError:

                latency_ms = round((self._clock() - start) * 1000)
                breaker.record_failure()
                self._quota_governor.record_result(provider, success=False)

                return ProviderExecutionResult(
                    provider=provider, state=ProviderExecutionState.TIMEOUT,
                    error=f"Timed out after {self._policy.timeout_seconds}s", latency_ms=latency_ms,
                )

            except Exception as error:

                latency_ms = round((self._clock() - start) * 1000)
                breaker.record_failure()
                self._quota_governor.record_result(provider, success=False)

                return ProviderExecutionResult(
                    provider=provider, state=ProviderExecutionState.ERROR,
                    error=str(error), latency_ms=latency_ms,
                )

        latency_ms = round((self._clock() - start) * 1000)
        breaker.record_success()
        self._quota_governor.record_result(provider, success=True)
        self._cache_set(provider, cache_key, value)

        return ProviderExecutionResult(
            provider=provider, state=ProviderExecutionState.SUCCESS,
            value=value, latency_ms=latency_ms,
        )
