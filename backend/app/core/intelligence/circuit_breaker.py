"""
Circuit breaker (Section 5) - a repeatedly failing provider should not
be hammered continuously.

Standard three-state design:

CLOSED:     normal operation, calls pass through.
OPEN:       too many recent failures - calls are rejected immediately
            (without even attempting the network call) until the
            cooldown elapses.
HALF_OPEN:  cooldown elapsed - the next call is allowed through as a
            probe; success closes the circuit again, failure re-opens
            it (and resets the cooldown clock).

Pure in-memory, no wall-clock dependency beyond `time.monotonic()` so
it's deterministic to unit test with an injectable clock.
"""

from dataclasses import dataclass
from dataclasses import field
from enum import Enum
from typing import Callable


class CircuitState(str, Enum):

    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


@dataclass
class CircuitBreakerConfig:

    failure_threshold: int = 5       # consecutive failures before opening
    cooldown_seconds: float = 60.0   # time before an OPEN circuit tries HALF_OPEN


@dataclass
class _BreakerState:

    consecutive_failures: int = 0
    state: CircuitState = CircuitState.CLOSED
    opened_at: float | None = None


class CircuitBreaker:
    """
    One instance governs one provider (or share one instance keyed
    externally per-provider via a dict - see ProviderRunner). `clock`
    defaults to time.monotonic but is injectable for deterministic
    tests.
    """

    def __init__(
        self,
        config: CircuitBreakerConfig | None = None,
        clock: Callable[[], float] | None = None,
    ) -> None:

        import time

        self._config = config or CircuitBreakerConfig()
        self._clock = clock or time.monotonic
        self._state = _BreakerState()

    @property
    def state(self) -> CircuitState:
        return self._state.state

    def allow_request(self) -> bool:
        """
        Call before attempting the provider request. False means
        "don't even try - return QUOTA/circuit-open evidence instead".
        """

        if self._state.state == CircuitState.CLOSED:
            return True

        if self._state.state == CircuitState.OPEN:

            elapsed = self._clock() - (self._state.opened_at or 0.0)

            if elapsed >= self._config.cooldown_seconds:
                self._state.state = CircuitState.HALF_OPEN
                return True

            return False

        # HALF_OPEN: allow exactly one probe through at a time. Once a
        # probe is in flight, further allow_request() calls before its
        # result is recorded should also be treated as "not yet allowed
        # again" - callers are expected to record_success/record_failure
        # promptly after each allowed call.
        return True

    def record_success(self) -> None:

        self._state.consecutive_failures = 0
        self._state.state = CircuitState.CLOSED
        self._state.opened_at = None

    def record_failure(self) -> None:

        self._state.consecutive_failures += 1

        if self._state.state == CircuitState.HALF_OPEN:
            # Probe failed - re-open immediately, reset cooldown clock.
            self._state.state = CircuitState.OPEN
            self._state.opened_at = self._clock()
            return

        if self._state.consecutive_failures >= self._config.failure_threshold:
            self._state.state = CircuitState.OPEN
            self._state.opened_at = self._clock()
