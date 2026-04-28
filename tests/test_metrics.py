"""
Tests for the Performance Monitoring System (Phase 7).
Run with: python -m pytest tests/test_metrics.py -v
"""

import time

import pytest

from core.metrics.collector import MetricsCollector, JobMetrics, PhaseMetric


class TestMetricsCollector:
    """Tests for the metrics collection system."""

    def test_record_metric(self):
        """Basic metric recording works."""
        mc = MetricsCollector()
        mc.record("job-1", "correlation", 150.0, 25.0)

        metrics = mc.get_metrics("job-1")
        assert metrics is not None
        assert metrics["job_id"] == "job-1"
        assert len(metrics["phases"]) == 1
        assert metrics["phases"][0]["phase"] == "correlation"
        assert metrics["phases"][0]["duration_ms"] == 150.0

    def test_multiple_phases(self):
        """Multiple phases are recorded in order."""
        mc = MetricsCollector()
        mc.record("job-1", "correlation", 100.0)
        mc.record("job-1", "enrichment", 50.0)
        mc.record("job-1", "timeline", 75.0)

        metrics = mc.get_metrics("job-1")
        assert len(metrics["phases"]) == 3
        assert metrics["total_duration_ms"] == 225.0

    def test_peak_memory_tracking(self):
        """Peak memory is tracked as max across phases."""
        mc = MetricsCollector()
        mc.record("job-1", "phase_a", 100.0, 10.0)
        mc.record("job-1", "phase_b", 100.0, 50.0)
        mc.record("job-1", "phase_c", 100.0, 30.0)

        metrics = mc.get_metrics("job-1")
        assert metrics["peak_memory_mb"] == 50.0

    def test_context_manager(self):
        """Context manager tracks execution time."""
        mc = MetricsCollector()

        with mc.track("job-1", "test_phase"):
            time.sleep(0.01)

        metrics = mc.get_metrics("job-1")
        assert len(metrics["phases"]) == 1
        assert metrics["phases"][0]["duration_ms"] > 0
        assert metrics["phases"][0]["phase"] == "test_phase"

    def test_context_manager_on_error(self):
        """Context manager records metrics even on exception."""
        mc = MetricsCollector()

        with pytest.raises(ValueError):
            with mc.track("job-1", "fail_phase"):
                raise ValueError("boom")

        # Metrics should still be recorded (duration may be ~0 for instant exceptions)
        metrics = mc.get_metrics("job-1")
        assert len(metrics["phases"]) == 1
        assert metrics["phases"][0]["duration_ms"] >= 0
        assert metrics["phases"][0]["phase"] == "fail_phase"

    def test_get_nonexistent_job(self):
        """Non-existent job returns None."""
        mc = MetricsCollector()
        assert mc.get_metrics("nonexistent") is None

    def test_summary_empty(self):
        """Summary with no jobs returns zeros."""
        mc = MetricsCollector()
        summary = mc.get_summary()
        assert summary["total_jobs"] == 0
        assert summary["avg_duration_ms"] == 0.0

    def test_summary_with_data(self):
        """Summary aggregates across multiple jobs."""
        mc = MetricsCollector()
        mc.record("job-1", "correlation", 100.0)
        mc.record("job-1", "timeline", 200.0)
        mc.record("job-2", "correlation", 150.0)
        mc.record("job-2", "timeline", 250.0)

        summary = mc.get_summary()
        assert summary["total_jobs"] == 2
        assert summary["avg_duration_ms"] == 350.0  # (300 + 400) / 2
        assert summary["max_duration_ms"] == 400.0
        assert "correlation" in summary["phase_averages"]
        assert summary["phase_averages"]["correlation"] == 125.0  # (100 + 150) / 2

    def test_list_job_ids(self):
        """List returns all tracked job IDs."""
        mc = MetricsCollector()
        mc.record("job-a", "p1", 10.0)
        mc.record("job-b", "p1", 20.0)

        ids = mc.list_job_ids()
        assert set(ids) == {"job-a", "job-b"}

    def test_thread_safety(self):
        """Concurrent recording doesn't crash."""
        import threading

        mc = MetricsCollector()
        errors = []

        def record_metrics(job_id: str):
            try:
                for i in range(100):
                    mc.record(job_id, f"phase_{i}", float(i))
            except Exception as e:
                errors.append(e)

        threads = [
            threading.Thread(target=record_metrics, args=(f"job-{i}",))
            for i in range(5)
        ]

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0
        assert len(mc.list_job_ids()) == 5


# ---------------------------------------------------------------------------
# Performance
# ---------------------------------------------------------------------------

class TestMetricsPerformance:
    """Performance tests for metrics collection."""

    def test_high_volume_recording(self):
        """Recording 10k metrics completes quickly."""
        mc = MetricsCollector()

        start = time.time()
        for i in range(10_000):
            mc.record(f"job-{i % 100}", f"phase_{i % 10}", float(i))
        elapsed = time.time() - start

        assert elapsed < 2.0, f"Took {elapsed:.2f}s — too slow for 10k records"
        assert mc.get_summary()["total_jobs"] == 100
