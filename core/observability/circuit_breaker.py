"""
Observability — Circuit Breaker
=================================
Protects the query engine from cascading failures.
After a configurable number of consecutive failures,
the circuit opens and rejects requests for a cooldown period.
"""

import threading
import time
from enum import Enum
from typing import Any, Dict


class CircuitState(Enum):
    CLOSED = "closed"       # Normal — requests pass through
    OPEN = "open"           # Tripped — requests rejected
    HALF_OPEN = "half_open" # Testing — one request allowed through


class CircuitBreaker:
    """
    Thread-safe circuit breaker for the query engine.

    Parameters
    ----------
    failure_threshold : int
        Number of consecutive failures before the circuit opens.
    cooldown_seconds : float
        How long the circuit stays open before allowing a test request.
    """

    def __init__(
        self,
        failure_threshold: int = 3,
        cooldown_seconds: float = 5.0,
    ) -> None:
        self._lock = threading.Lock()
        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._failure_threshold = failure_threshold
        self._cooldown = cooldown_seconds
        self._last_failure_time = 0.0
        self._total_trips = 0

    @property
    def state(self) -> CircuitState:
        """Current circuit state."""
        with self._lock:
            return self._get_effective_state()

    def _get_effective_state(self) -> CircuitState:
        """Check if cooldown has elapsed (transition OPEN → HALF_OPEN)."""
        if self._state == CircuitState.OPEN:
            if time.time() - self._last_failure_time >= self._cooldown:
                return CircuitState.HALF_OPEN
        return self._state

    def allow_request(self) -> bool:
        """
        Check if a request should be allowed through.

        Returns
        -------
        bool
            True if the request can proceed, False if circuit is open.
        """
        with self._lock:
            effective = self._get_effective_state()

            if effective == CircuitState.CLOSED:
                return True

            if effective == CircuitState.HALF_OPEN:
                # Allow one test request
                self._state = CircuitState.HALF_OPEN
                return True

            # OPEN — reject
            return False

    def record_success(self) -> None:
        """Record a successful execution. Resets the circuit if half-open."""
        with self._lock:
            self._failure_count = 0
            self._state = CircuitState.CLOSED

    def record_failure(self) -> None:
        """Record a failed execution. May trip the circuit."""
        with self._lock:
            self._failure_count += 1
            self._last_failure_time = time.time()

            if self._failure_count >= self._failure_threshold:
                if self._state != CircuitState.OPEN:
                    self._total_trips += 1
                self._state = CircuitState.OPEN

    def get_status(self) -> Dict[str, Any]:
        """Return diagnostic status."""
        with self._lock:
            return {
                "state": self._get_effective_state().value,
                "failure_count": self._failure_count,
                "failure_threshold": self._failure_threshold,
                "cooldown_seconds": self._cooldown,
                "total_trips": self._total_trips,
            }
