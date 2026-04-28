"""
Observability — Hunting Performance Metrics
=============================================
Tracks query execution times, error rates, and throughput
for the threat hunting subsystem.
"""

import statistics
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, List, Any


@dataclass
class QueryRecord:
    """Single query execution record."""
    timestamp: float
    duration_ms: float
    success: bool
    result_count: int = 0


class HuntingMetrics:
    """
    Lightweight in-memory metrics collector for hunting queries.

    Thread-safe. Maintains a sliding window of recent query records
    for real-time statistics (last 5 minutes by default).

    Parameters
    ----------
    window_seconds : int
        Sliding window duration in seconds (default: 300 = 5 min).
    """

    def __init__(self, window_seconds: int = 300) -> None:
        self._lock = threading.Lock()
        self._records: List[QueryRecord] = []
        self._window = window_seconds

    def record(
        self,
        duration_ms: float,
        success: bool = True,
        result_count: int = 0,
    ) -> None:
        """Record a query execution."""
        now = time.time()
        with self._lock:
            self._records.append(QueryRecord(
                timestamp=now,
                duration_ms=duration_ms,
                success=success,
                result_count=result_count,
            ))
            self._prune(now)

    def _prune(self, now: float) -> None:
        """Remove records outside the sliding window."""
        cutoff = now - self._window
        self._records = [r for r in self._records if r.timestamp >= cutoff]

    def get_stats(self) -> Dict[str, Any]:
        """
        Compute hunting performance statistics.

        Returns
        -------
        dict
            Contains avg_query_time, p95_query_time, queries_per_minute,
            error_rate, total_queries, window_seconds.
        """
        now = time.time()
        with self._lock:
            self._prune(now)
            records = list(self._records)

        if not records:
            return {
                "avg_query_time": 0.0,
                "p95_query_time": 0.0,
                "queries_per_minute": 0.0,
                "error_rate": 0.0,
                "total_queries": 0,
                "window_seconds": self._window,
            }

        durations = [r.duration_ms for r in records]
        errors = sum(1 for r in records if not r.success)
        total = len(records)

        # Time span in minutes
        time_span = max((now - records[0].timestamp) / 60, 1 / 60)

        avg_time = round(statistics.mean(durations), 2)

        # P95: sort and take 95th percentile
        sorted_d = sorted(durations)
        p95_idx = int(len(sorted_d) * 0.95)
        p95_time = round(sorted_d[min(p95_idx, len(sorted_d) - 1)], 2)

        return {
            "avg_query_time": avg_time,
            "p95_query_time": p95_time,
            "queries_per_minute": round(total / time_span, 2),
            "error_rate": round(errors / total, 4) if total > 0 else 0.0,
            "total_queries": total,
            "total_errors": errors,
            "avg_result_count": round(
                statistics.mean([r.result_count for r in records]), 1
            ),
            "window_seconds": self._window,
        }
