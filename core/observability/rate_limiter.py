"""
Observability — Lightweight Rate Limiter
==========================================
Token-bucket rate limiter keyed by (endpoint, user_id) or
(endpoint, source). No external dependencies.
"""

import threading
import time
from dataclasses import dataclass, field
from typing import Dict, Tuple


@dataclass
class TokenBucket:
    """Simple token bucket for rate limiting."""
    capacity: int
    refill_rate: float  # tokens per second
    tokens: float = 0.0
    last_refill: float = field(default_factory=time.time)

    def try_consume(self, now: float, count: int = 1) -> bool:
        """
        Attempt to consume tokens. Returns True if allowed.
        """
        elapsed = now - self.last_refill
        self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_rate)
        self.last_refill = now

        if self.tokens >= count:
            self.tokens -= count
            return True
        return False


class RateLimiter:
    """
    Thread-safe in-memory rate limiter using token buckets.

    Supports per-key rate limiting (e.g., per user+endpoint or
    per source+endpoint).

    Parameters
    ----------
    default_capacity : int
        Default bucket capacity (max burst).
    default_rate : float
        Default refill rate (tokens per second).
    cleanup_interval : int
        Seconds between stale bucket cleanup passes.
    """

    def __init__(
        self,
        default_capacity: int = 10,
        default_rate: float = 1.0,
        cleanup_interval: int = 60,
    ) -> None:
        self._lock = threading.Lock()
        self._buckets: Dict[Tuple[str, str], TokenBucket] = {}
        self._default_capacity = default_capacity
        self._default_rate = default_rate
        self._cleanup_interval = cleanup_interval
        self._last_cleanup = time.time()

    def check(
        self,
        key: str,
        scope: str = "default",
        capacity: int | None = None,
        rate: float | None = None,
    ) -> bool:
        """
        Check if a request is allowed.

        Parameters
        ----------
        key : str
            Rate limit key (e.g., user_id, source IP).
        scope : str
            Scope identifier (e.g., "hunt_query", "ingest_event").
        capacity : int, optional
            Override default capacity for this check.
        rate : float, optional
            Override default rate for this check.

        Returns
        -------
        bool
            True if request is allowed, False if rate limited.
        """
        now = time.time()
        bucket_key = (scope, key)

        cap = capacity if capacity is not None else self._default_capacity
        r = rate if rate is not None else self._default_rate

        with self._lock:
            # Periodic cleanup
            if now - self._last_cleanup > self._cleanup_interval:
                self._cleanup(now)
                self._last_cleanup = now

            if bucket_key not in self._buckets:
                self._buckets[bucket_key] = TokenBucket(
                    capacity=cap,
                    refill_rate=r,
                    tokens=cap,  # Start full
                    last_refill=now,
                )

            return self._buckets[bucket_key].try_consume(now)

    def _cleanup(self, now: float) -> None:
        """Remove stale buckets that haven't been accessed recently."""
        stale_threshold = now - self._cleanup_interval * 5
        stale_keys = [
            k for k, b in self._buckets.items()
            if b.last_refill < stale_threshold
        ]
        for k in stale_keys:
            del self._buckets[k]

    def get_bucket_count(self) -> int:
        """Return number of active buckets (for diagnostics)."""
        with self._lock:
            return len(self._buckets)
