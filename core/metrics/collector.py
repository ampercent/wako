"""
Metrics Collector — Runtime performance tracking.
=====================================================
Measures and records execution time, memory usage, and
throughput for each phase of the forensic analysis pipeline.
"""

import logging
import threading
import time
import tracemalloc
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Generator, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class PhaseMetric:
    """Performance data for a single pipeline phase."""
    phase: str
    duration_ms: float
    memory_peak_mb: float
    start_time: str
    end_time: str


@dataclass
class JobMetrics:
    """Aggregated metrics for a single job."""
    job_id: str
    phases: List[PhaseMetric] = field(default_factory=list)
    total_duration_ms: float = 0.0
    peak_memory_mb: float = 0.0
    started_at: Optional[str] = None
    completed_at: Optional[str] = None


class MetricsCollector:
    """
    Collects runtime performance metrics per job and per phase.

    Thread-safe. Metrics are stored in memory with optional
    SQLite persistence.

    Parameters
    ----------
    enable_tracemalloc : bool
        Whether to track memory usage via ``tracemalloc``.
        Disabled by default for performance (adds ~5% overhead).
    """

    def __init__(self, enable_tracemalloc: bool = False) -> None:
        self._lock = threading.Lock()
        self._jobs: Dict[str, JobMetrics] = {}
        self._enable_tracemalloc = enable_tracemalloc

        if enable_tracemalloc and not tracemalloc.is_tracing():
            tracemalloc.start()

    # ------------------------------------------------------------------
    # Recording
    # ------------------------------------------------------------------

    def record(
        self,
        job_id: str,
        phase: str,
        duration_ms: float,
        memory_mb: float = 0.0,
    ) -> None:
        """
        Record a phase execution metric.

        Parameters
        ----------
        job_id : str
            Associated job ID.
        phase : str
            Pipeline phase name (e.g., ``"correlation"``).
        duration_ms : float
            Execution time in milliseconds.
        memory_mb : float
            Peak memory usage in megabytes.
        """
        now = datetime.now(timezone.utc).isoformat()

        metric = PhaseMetric(
            phase=phase,
            duration_ms=round(duration_ms, 2),
            memory_peak_mb=round(memory_mb, 2),
            start_time=now,
            end_time=now,
        )

        with self._lock:
            if job_id not in self._jobs:
                self._jobs[job_id] = JobMetrics(job_id=job_id, started_at=now)

            jm = self._jobs[job_id]
            jm.phases.append(metric)
            jm.total_duration_ms += duration_ms
            jm.peak_memory_mb = max(jm.peak_memory_mb, memory_mb)
            jm.completed_at = now

    # ------------------------------------------------------------------
    # Context manager for timed + memory-tracked blocks
    # ------------------------------------------------------------------

    @contextmanager
    def track(self, job_id: str, phase: str) -> Generator[None, None, None]:
        """
        Context manager that auto-records timing and memory for a code block.

        Usage::

            with metrics.track(job_id, "correlation"):
                result = correlate_artifacts(...)

        Parameters
        ----------
        job_id : str
            Associated job ID.
        phase : str
            Pipeline phase name.
        """
        # Capture memory before
        mem_before = 0.0
        if self._enable_tracemalloc and tracemalloc.is_tracing():
            mem_before = tracemalloc.get_traced_memory()[1] / (1024 * 1024)

        start = time.perf_counter()

        try:
            yield
        finally:
            elapsed_ms = (time.perf_counter() - start) * 1000

            # Capture memory after
            mem_after = 0.0
            if self._enable_tracemalloc and tracemalloc.is_tracing():
                mem_after = tracemalloc.get_traced_memory()[1] / (1024 * 1024)

            peak_mb = max(mem_after - mem_before, 0.0) if self._enable_tracemalloc else 0.0

            self.record(job_id, phase, elapsed_ms, peak_mb)
            logger.debug(
                f"Metrics [{job_id}] {phase}: {elapsed_ms:.1f}ms, "
                f"mem: {peak_mb:.1f}MB"
            )

    # ------------------------------------------------------------------
    # Query
    # ------------------------------------------------------------------

    def get_metrics(self, job_id: str) -> Optional[Dict[str, Any]]:
        """
        Get per-phase metrics for a specific job.

        Returns
        -------
        dict or None
            Contains ``job_id``, ``total_duration_ms``, ``peak_memory_mb``,
            and ``phases`` list.
        """
        with self._lock:
            jm = self._jobs.get(job_id)
            if jm is None:
                return None

            return {
                "job_id": jm.job_id,
                "total_duration_ms": round(jm.total_duration_ms, 2),
                "peak_memory_mb": round(jm.peak_memory_mb, 2),
                "started_at": jm.started_at,
                "completed_at": jm.completed_at,
                "phases": [
                    {
                        "phase": p.phase,
                        "duration_ms": p.duration_ms,
                        "memory_peak_mb": p.memory_peak_mb,
                    }
                    for p in jm.phases
                ],
            }

    def get_summary(self) -> Dict[str, Any]:
        """
        Get aggregate metrics across all jobs.

        Returns
        -------
        dict
            Contains ``total_jobs``, ``avg_duration_ms``,
            ``max_duration_ms``, ``phase_averages``.
        """
        with self._lock:
            if not self._jobs:
                return {
                    "total_jobs": 0,
                    "avg_duration_ms": 0.0,
                    "max_duration_ms": 0.0,
                    "phase_averages": {},
                }

            total = len(self._jobs)
            durations = [jm.total_duration_ms for jm in self._jobs.values()]
            avg_dur = sum(durations) / total
            max_dur = max(durations)

            # Per-phase averages
            phase_totals: Dict[str, List[float]] = {}
            for jm in self._jobs.values():
                for p in jm.phases:
                    phase_totals.setdefault(p.phase, []).append(p.duration_ms)

            phase_avgs = {
                phase: round(sum(vals) / len(vals), 2)
                for phase, vals in phase_totals.items()
            }

            return {
                "total_jobs": total,
                "avg_duration_ms": round(avg_dur, 2),
                "max_duration_ms": round(max_dur, 2),
                "phase_averages": phase_avgs,
            }

    def list_job_ids(self) -> List[str]:
        """Return all tracked job IDs."""
        with self._lock:
            return list(self._jobs.keys())
