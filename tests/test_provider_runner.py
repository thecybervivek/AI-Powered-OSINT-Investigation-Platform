import asyncio

import pytest

from backend.app.core.intelligence.circuit_breaker import CircuitBreakerConfig
from backend.app.core.intelligence.provider_runner import ProviderExecutionPolicy
from backend.app.core.intelligence.provider_runner import ProviderExecutionState
from backend.app.core.intelligence.provider_runner import ProviderRunner
from backend.app.core.intelligence.quota_governor import ProviderQuotaPolicy
from backend.app.core.intelligence.quota_governor import QuotaGovernor


@pytest.mark.anyio
async def test_successful_call():

    runner = ProviderRunner(ProviderExecutionPolicy(timeout_seconds=1.0))

    async def ok_call():
        return {"result": "data"}

    result = await runner.run("vt", "target1", ok_call)

    assert result.state == ProviderExecutionState.SUCCESS
    assert result.value == {"result": "data"}
    assert result.from_cache is False


@pytest.mark.anyio
async def test_timeout_does_not_block_indefinitely():

    runner = ProviderRunner(ProviderExecutionPolicy(timeout_seconds=0.05))

    async def slow_call():
        await asyncio.sleep(0.3)
        return "too late"

    result = await runner.run("slow_provider", "t", slow_call)

    assert result.state == ProviderExecutionState.TIMEOUT


@pytest.mark.anyio
async def test_exception_is_captured_as_error_state():

    runner = ProviderRunner(ProviderExecutionPolicy(timeout_seconds=1.0))

    async def broken_call():
        raise ValueError("boom")

    result = await runner.run("broken", "t", broken_call)

    assert result.state == ProviderExecutionState.ERROR
    assert "boom" in result.error


@pytest.mark.anyio
async def test_circuit_breaker_stops_calling_repeatedly_failing_provider():

    call_count = 0

    async def always_fails():
        nonlocal call_count
        call_count += 1
        raise RuntimeError("always fails")

    runner = ProviderRunner(
        ProviderExecutionPolicy(
            timeout_seconds=1.0,
            circuit_breaker_config=CircuitBreakerConfig(failure_threshold=3, cooldown_seconds=999),
        )
    )

    for _ in range(3):
        result = await runner.run("flaky", "t", always_fails)
        assert result.state == ProviderExecutionState.ERROR

    assert call_count == 3

    result = await runner.run("flaky", "t", always_fails)

    assert result.state == ProviderExecutionState.CIRCUIT_OPEN
    assert call_count == 3  # the 4th call never actually invoked always_fails


@pytest.mark.anyio
async def test_quota_exhaustion_blocks_without_invoking_the_call():

    quota_calls = 0

    async def quota_tracked_call():
        nonlocal quota_calls
        quota_calls += 1
        return "ok"

    gov = QuotaGovernor()
    gov.register_policy(ProviderQuotaPolicy(provider="shodan", daily_limit=1))
    runner = ProviderRunner(ProviderExecutionPolicy(timeout_seconds=1.0), quota_governor=gov)

    r1 = await runner.run("shodan", "a", quota_tracked_call)
    assert r1.state == ProviderExecutionState.SUCCESS

    r2 = await runner.run("shodan", "b", quota_tracked_call)
    assert r2.state == ProviderExecutionState.QUOTA_EXHAUSTED
    assert quota_calls == 1


@pytest.mark.anyio
async def test_repeated_call_for_same_key_served_from_cache():

    cache_calls = 0

    async def cached_call():
        nonlocal cache_calls
        cache_calls += 1
        return "cached-value"

    runner = ProviderRunner(ProviderExecutionPolicy(timeout_seconds=1.0, cache_ttl_seconds=60.0))

    r1 = await runner.run("geo", "same-target", cached_call)
    r2 = await runner.run("geo", "same-target", cached_call)

    assert r1.state == ProviderExecutionState.SUCCESS and r1.from_cache is False
    assert r2.state == ProviderExecutionState.CACHE_HIT and r2.from_cache is True
    assert r2.value == "cached-value"
    assert cache_calls == 1
