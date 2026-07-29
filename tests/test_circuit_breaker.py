from backend.app.core.intelligence.circuit_breaker import CircuitBreaker
from backend.app.core.intelligence.circuit_breaker import CircuitBreakerConfig
from backend.app.core.intelligence.circuit_breaker import CircuitState


class _FakeClock:

    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t

    def advance(self, seconds):
        self.t += seconds


def test_closed_by_default_and_allows_requests():

    cb = CircuitBreaker(clock=_FakeClock())

    assert cb.state == CircuitState.CLOSED
    assert cb.allow_request() is True


def test_stays_closed_below_failure_threshold():

    cb = CircuitBreaker(CircuitBreakerConfig(failure_threshold=3), clock=_FakeClock())

    cb.record_failure()
    cb.record_failure()

    assert cb.state == CircuitState.CLOSED
    assert cb.allow_request() is True


def test_opens_at_failure_threshold_and_rejects():

    cb = CircuitBreaker(CircuitBreakerConfig(failure_threshold=3), clock=_FakeClock())

    for _ in range(3):
        cb.record_failure()

    assert cb.state == CircuitState.OPEN
    assert cb.allow_request() is False


def test_stays_open_before_cooldown_elapses():

    clock = _FakeClock()
    cb = CircuitBreaker(CircuitBreakerConfig(failure_threshold=1, cooldown_seconds=30.0), clock=clock)

    cb.record_failure()
    clock.advance(10.0)

    assert cb.allow_request() is False
    assert cb.state == CircuitState.OPEN


def test_transitions_to_half_open_after_cooldown():

    clock = _FakeClock()
    cb = CircuitBreaker(CircuitBreakerConfig(failure_threshold=1, cooldown_seconds=30.0), clock=clock)

    cb.record_failure()
    clock.advance(35.0)

    assert cb.allow_request() is True
    assert cb.state == CircuitState.HALF_OPEN


def test_successful_probe_closes_the_circuit():

    clock = _FakeClock()
    cb = CircuitBreaker(CircuitBreakerConfig(failure_threshold=1, cooldown_seconds=30.0), clock=clock)

    cb.record_failure()
    clock.advance(35.0)
    cb.allow_request()
    cb.record_success()

    assert cb.state == CircuitState.CLOSED
    assert cb.allow_request() is True


def test_failed_probe_reopens_immediately_without_needing_fresh_failures():

    clock = _FakeClock()
    cb = CircuitBreaker(CircuitBreakerConfig(failure_threshold=3, cooldown_seconds=30.0), clock=clock)

    for _ in range(3):
        cb.record_failure()

    clock.advance(31.0)
    cb.allow_request()  # transitions to HALF_OPEN
    cb.record_failure()  # probe fails

    assert cb.state == CircuitState.OPEN
    assert cb.allow_request() is False
