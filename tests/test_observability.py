"""Quick smoke test for all observability modules."""

import time
from core.observability import RequestLogger, HuntingMetrics, RateLimiter, CircuitBreaker


def test_request_logger():
    rl = RequestLogger(buffer_size=10)
    with rl.track_request("/test", "GET") as log:
        log.result_count = 5
        time.sleep(0.01)
    recent = rl.get_recent(1)
    assert recent[0]["endpoint"] == "/test"
    assert recent[0]["result_count"] == 5
    assert recent[0]["execution_time_ms"] > 0
    print(f"  RequestLogger: OK ({recent[0]['execution_time_ms']:.1f}ms tracked)")


def test_hunting_metrics():
    hm = HuntingMetrics(window_seconds=60)
    hm.record(12.5, success=True, result_count=10)
    hm.record(25.0, success=True, result_count=20)
    hm.record(100.0, success=False, result_count=0)
    stats = hm.get_stats()
    assert stats["total_queries"] == 3
    assert stats["total_errors"] == 1
    assert stats["avg_query_time"] > 0
    print(f"  HuntingMetrics: OK (avg={stats['avg_query_time']}ms, errors={stats['total_errors']})")


def test_rate_limiter():
    limiter = RateLimiter(default_capacity=3, default_rate=0.5)
    assert limiter.check("user1", "test") is True
    assert limiter.check("user1", "test") is True
    assert limiter.check("user1", "test") is True
    assert limiter.check("user1", "test") is False  # 4th blocked
    assert limiter.check("user2", "test") is True    # Different user OK
    print(f"  RateLimiter: OK (buckets={limiter.get_bucket_count()})")


def test_circuit_breaker():
    cb = CircuitBreaker(failure_threshold=2, cooldown_seconds=0.1)
    assert cb.allow_request() is True
    cb.record_failure()
    assert cb.allow_request() is True   # 1 failure, still closed
    cb.record_failure()
    assert cb.allow_request() is False  # 2 failures, now open
    time.sleep(0.15)
    assert cb.allow_request() is True   # Half-open after cooldown
    cb.record_success()
    assert cb.state.value == "closed"
    status = cb.get_status()
    print(f"  CircuitBreaker: OK (trips={status['total_trips']})")


if __name__ == "__main__":
    print("\nObservability Module Tests")
    print("=" * 40)
    test_request_logger()
    test_hunting_metrics()
    test_rate_limiter()
    test_circuit_breaker()
    print("=" * 40)
    print("ALL TESTS PASSED\n")
