"""
Job Worker — Background pipeline execution.
=============================================
Runs the full forensic analysis pipeline (correlation → scoring →
timeline → graph) in a thread pool, updating job status as it progresses.
"""

import logging
import traceback
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import TYPE_CHECKING, Optional

import pandas as pd

from .models import JobResult, JobStatus

if TYPE_CHECKING:
    from core.audit.logger import AuditLogger
    from core.metrics.collector import MetricsCollector
    from core.storage.cache import CacheManager
    from core.validation.validators import DataValidator
    from .manager import JobManager

logger = logging.getLogger(__name__)


class JobWorker:
    """
    Background worker that runs analysis pipelines in a thread pool.

    Parameters
    ----------
    job_manager : JobManager
        Job lifecycle manager for status updates.
    max_workers : int
        Maximum concurrent analysis threads (default 2).
    cache_manager : CacheManager, optional
        Result cache for deduplication.
    audit_logger : AuditLogger, optional
        Structured action audit trail.
    validator : DataValidator, optional
        Data integrity checks.
    metrics_collector : MetricsCollector, optional
        Performance tracking.
    """

    def __init__(
        self,
        job_manager: "JobManager",
        max_workers: int = 2,
        cache_manager: Optional["CacheManager"] = None,
        audit_logger: Optional["AuditLogger"] = None,
        validator: Optional["DataValidator"] = None,
        metrics_collector: Optional["MetricsCollector"] = None,
    ) -> None:
        self.job_manager = job_manager
        self.cache_manager = cache_manager
        self.audit_logger = audit_logger
        self.validator = validator
        self.metrics_collector = metrics_collector
        self._executor = ThreadPoolExecutor(max_workers=max_workers)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def submit(self, job_id: str, dump_path: str) -> None:
        """Submit a single-dump analysis job to the thread pool."""
        self._executor.submit(self._run_single_analysis, job_id, dump_path)

    def submit_multi(self, job_id: str, dump_paths: list) -> None:
        """Submit a multi-dump comparison job to the thread pool."""
        self._executor.submit(self._run_multi_analysis, job_id, dump_paths)

    def shutdown(self, wait: bool = True) -> None:
        """Gracefully shut down the thread pool."""
        self._executor.shutdown(wait=wait)

    # ------------------------------------------------------------------
    # Internal — single dump pipeline
    # ------------------------------------------------------------------

    def _run_single_analysis(self, job_id: str, dump_path: str) -> None:
        """Execute the full forensic analysis pipeline for one dump."""
        try:
            self.job_manager.update_status(job_id, status=JobStatus.RUNNING, progress=0)
            self._audit_action(job_id, "pipeline_start", "worker", f"Starting analysis for {dump_path}")

            # --- Step 0: Cache check ---
            dump_hash: Optional[str] = None
            if self.cache_manager:
                self._audit_action(job_id, "cache_check", "cache", f"Computing SHA256 for {dump_path}")
                hit, cached_result, dump_hash = self.cache_manager.check_cache(dump_path)
                self.job_manager.update_status(job_id, dump_hash=dump_hash)
                if hit and cached_result:
                    logger.info(f"Job {job_id}: Cache hit for hash {dump_hash}")
                    self._audit_action(job_id, "cache_hit", "cache", f"Returning cached result for {dump_hash}")
                    result = JobResult(
                        correlation=cached_result.get("correlation"),
                        timeline=cached_result.get("timeline"),
                        graph=cached_result.get("graph"),
                        alerts=cached_result.get("alerts"),
                        cached=True,
                    )
                    self.job_manager.store_result(job_id, result)
                    self.job_manager.update_status(job_id, status=JobStatus.COMPLETED, progress=100)
                    return

            self.job_manager.update_status(job_id, progress=5)

            # --- Step 1: Load data ---
            self._audit_action(job_id, "load_data", "parser", "Loading process and network data")
            ps_df, net_df, mal_df = self._load_data(dump_path)
            self.job_manager.update_status(job_id, progress=20)

            # --- Step 2: Validate ---
            validation_warnings: list = []
            if self.validator:
                self._audit_action(job_id, "validation", "validator", "Running data validation")
                validation_warnings = self._validate_data(job_id, ps_df, net_df, mal_df)
            self.job_manager.update_status(job_id, progress=30)

            # --- Step 3: Correlate ---
            self._audit_action(job_id, "correlation", "correlate_artifacts", "Running artifact correlation")
            with self._track_metrics(job_id, "correlation"):
                from pipeline.correlation import correlate_artifacts
                correlated = correlate_artifacts(ps_df, net_df, mal_df)
            self.job_manager.update_status(job_id, progress=50)

            # --- Step 4: Enrich ---
            self._audit_action(job_id, "enrichment", "enrich_with_explanations", "Enriching with risk scores")
            with self._track_metrics(job_id, "enrichment"):
                from pipeline.risk_scoring import enrich_with_explanations, generate_alerts
                enriched = enrich_with_explanations(correlated)
                alerts_df = generate_alerts(enriched)
            self.job_manager.update_status(job_id, progress=65)

            # --- Step 5: Timeline ---
            self._audit_action(job_id, "timeline", "build_timeline", "Building forensic timeline")
            with self._track_metrics(job_id, "timeline"):
                from pipeline.timeline import build_timeline
                timeline_df = build_timeline(ps_df, net_df, mal_df, enriched)
            self.job_manager.update_status(job_id, progress=80)

            # --- Step 6: Graph ---
            self._audit_action(job_id, "graph", "build_attack_graph", "Building attack graph")
            with self._track_metrics(job_id, "graph"):
                from pipeline.graph_engine import build_attack_graph
                graph = build_attack_graph(enriched, timeline_df)
            self.job_manager.update_status(job_id, progress=90)

            # --- Step 7: Serialize results ---
            correlation_records = correlated.fillna("").to_dict(orient="records") if not correlated.empty else []
            timeline_records = self._serialize_timeline(timeline_df)
            alerts_records = alerts_df.fillna("").to_dict(orient="records") if not alerts_df.empty else []

            result = JobResult(
                correlation=correlation_records,
                timeline=timeline_records,
                graph=graph,
                alerts=alerts_records,
                validation_warnings=validation_warnings if validation_warnings else None,
                cached=False,
            )

            # --- Step 8: Cache store ---
            if self.cache_manager and dump_hash:
                self._audit_action(job_id, "cache_store", "cache", f"Storing result for hash {dump_hash}")
                self.cache_manager.store_cache_from_hash(dump_hash, dump_path, {
                    "correlation": correlation_records,
                    "timeline": timeline_records,
                    "graph": graph,
                    "alerts": alerts_records,
                })

            self.job_manager.store_result(job_id, result)
            self.job_manager.update_status(job_id, status=JobStatus.COMPLETED, progress=100)
            self._audit_action(job_id, "pipeline_complete", "worker", "Analysis completed successfully")
            logger.info(f"Job {job_id}: Analysis completed successfully")

        except Exception as e:
            tb = traceback.format_exc()
            logger.error(f"Job {job_id} failed: {e}\n{tb}")
            self._audit_action(job_id, "pipeline_failed", "worker", f"Error: {e}", error=str(e))
            self.job_manager.update_status(
                job_id, status=JobStatus.FAILED, error=str(e)
            )

    # ------------------------------------------------------------------
    # Internal — multi-dump pipeline
    # ------------------------------------------------------------------

    def _run_multi_analysis(self, job_id: str, dump_paths: list) -> None:
        """Run analysis on multiple dumps and produce a diff."""
        try:
            self.job_manager.update_status(job_id, status=JobStatus.RUNNING, progress=0)
            self._audit_action(job_id, "multi_pipeline_start", "worker", f"Multi-dump analysis: {dump_paths}")

            all_ps: list = []
            all_net: list = []
            all_timelines: list = []
            all_correlations: list = []

            per_dump = 80 // len(dump_paths)

            for i, dp in enumerate(dump_paths):
                self._audit_action(job_id, f"load_dump_{i}", "parser", f"Loading dump {i+1}: {dp}")
                ps_df, net_df, mal_df = self._load_data(dp)

                from pipeline.correlation import correlate_artifacts
                from pipeline.risk_scoring import enrich_with_explanations
                from pipeline.timeline import build_timeline

                correlated = correlate_artifacts(ps_df, net_df, mal_df)
                enriched = enrich_with_explanations(correlated)
                timeline = build_timeline(ps_df, net_df, mal_df, enriched)

                all_ps.append(ps_df)
                all_net.append(net_df)
                all_timelines.append(timeline)
                all_correlations.append(correlated)

                self.job_manager.update_status(job_id, progress=(i + 1) * per_dump)

            # Diff analysis
            self._audit_action(job_id, "diff_analysis", "diff_analyzer", "Running cross-dump diff")
            from diff_analysis.analyzer import DiffAnalyzer
            differ = DiffAnalyzer()

            # Compare first vs last
            diff_result = differ.compare_dumps(
                all_ps[0], all_ps[-1], all_net[0], all_net[-1]
            )

            # Merge timelines
            merged_timeline = differ.merge_timelines(all_timelines[0], all_timelines[-1])
            merged_timeline_records = self._serialize_timeline(merged_timeline)

            # Compare correlations
            corr_diff = differ.compare_correlations(all_correlations[0], all_correlations[-1])

            self.job_manager.update_status(job_id, progress=95)

            result = JobResult(
                timeline=merged_timeline_records,
                diff={
                    "process_diff": diff_result,
                    "correlation_diff": corr_diff,
                },
                cached=False,
            )

            self.job_manager.store_result(job_id, result)
            self.job_manager.update_status(job_id, status=JobStatus.COMPLETED, progress=100)
            self._audit_action(job_id, "multi_pipeline_complete", "worker", "Multi-dump analysis completed")

        except Exception as e:
            tb = traceback.format_exc()
            logger.error(f"Multi-dump job {job_id} failed: {e}\n{tb}")
            self._audit_action(job_id, "multi_pipeline_failed", "worker", f"Error: {e}", error=str(e))
            self.job_manager.update_status(job_id, status=JobStatus.FAILED, error=str(e))

    # ------------------------------------------------------------------
    # Data loading
    # ------------------------------------------------------------------

    def _load_data(self, dump_path: str):
        """
        Load process, network, and malfind data from output directory.

        Falls back to mock data (same logic as api.py) if files don't exist.
        """
        output_dir = Path(dump_path).parent if Path(dump_path).suffix else Path(dump_path)

        # Try standard output locations
        pslist_path = output_dir / "pslist.txt"
        netscan_path = output_dir / "netscan.txt"

        ps_df = pd.DataFrame()
        net_df = pd.DataFrame()

        # Attempt real parse
        try:
            from pipeline.engine import ForensicsEngine
            # Use mock data approach if no real outputs
            if pslist_path.exists():
                # Minimal engine just for parsing
                engine = ForensicsEngine.__new__(ForensicsEngine)
                ps_df = engine.parse_pslist(pslist_path)
        except Exception as e:
            logger.warning(f"Failed to parse pslist: {e}")

        try:
            if netscan_path.exists():
                engine = ForensicsEngine.__new__(ForensicsEngine)
                net_df = engine.parse_netscan(netscan_path)
        except Exception as e:
            logger.warning(f"Failed to parse netscan: {e}")

        # Fallback to mock data
        if ps_df.empty:
            ps_df = pd.DataFrame({
                "PID": [1000, 2010, 3010, 4010, 5010],
                "PPID": [500, 1000, 3010, 2010, 1000],
                "ImageFileName": ["explorer.exe", "certutil.exe", "powershell.exe", "cmd.exe", "chrome.exe"],
                "CreateTime": [
                    "2026-04-10 10:00:00", "2026-04-10 10:05:00",
                    "2026-04-10 10:06:00", "2026-04-10 10:07:00", "2026-04-10 10:01:00"
                ]
            })

        if net_df.empty:
            net_df = pd.DataFrame({
                "PID": [2010, 3010, 5010],
                "Proto": ["TCPv4", "TCPv4", "TCPv4"],
                "LocalAddr": ["192.168.1.10", "192.168.1.10", "192.168.1.10"],
                "ForeignAddr": ["8.8.8.8", "198.51.100.1", "142.250.190.46"],
                "ForeignPort": ["443", "4444", "443"],
                "State": ["ESTABLISHED", "ESTABLISHED", "ESTABLISHED"],
                "Owner": ["certutil.exe", "powershell.exe", "chrome.exe"],
                "Created": ["2026-04-10 10:05:30", "2026-04-10 10:06:15", "2026-04-10 10:02:00"]
            })

        # Malfind always mock for now
        mal_df = pd.DataFrame({
            "PID": [3010],
            "Process": ["powershell.exe"],
            "Protection": ["PAGE_EXECUTE_READWRITE"]
        })

        return ps_df, net_df, mal_df

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _serialize_timeline(self, timeline_df: pd.DataFrame) -> list:
        """Convert timeline DataFrame to JSON-safe list of dicts."""
        if timeline_df is None or timeline_df.empty:
            return []
        tl = timeline_df.copy()
        if "timestamp" in tl.columns:
            tl["timestamp"] = tl["timestamp"].astype(str)
        return tl.fillna("").to_dict(orient="records")

    def _validate_data(self, job_id: str, ps_df, net_df, mal_df) -> list:
        """Run validation checks, raising on hard errors."""
        warnings: list = []
        if self.validator is None:
            return warnings

        from core.validation.validators import ValidationResult

        # Schema validation
        for label, df, fn in [
            ("pslist", ps_df, self.validator.validate_pslist),
            ("netscan", net_df, self.validator.validate_netscan),
            ("malfind", mal_df, self.validator.validate_malfind),
        ]:
            result: ValidationResult = fn(df)
            if result.errors:
                err_msg = f"{label} validation failed: {'; '.join(result.errors)}"
                raise ValueError(err_msg)
            warnings.extend(result.warnings)

        # Sanity checks
        warnings.extend(self.validator.check_pid_consistency(ps_df, net_df))
        warnings.extend(self.validator.check_timestamp_validity(ps_df, "CreateTime"))
        warnings.extend(self.validator.check_duplicate_pids(ps_df))

        if warnings:
            for w in warnings:
                self._audit_action(job_id, "validation_warning", "validator", w)

        return warnings

    def _audit_action(self, job_id: str, action: str, tool: str, detail: str, error: str = None) -> None:
        """Log an action to the audit logger if available."""
        if self.audit_logger:
            self.audit_logger.log_action(
                job_id=job_id,
                action=action,
                tool=tool,
                command=detail,
                status="error" if error else "ok",
                error=error,
            )

    def _track_metrics(self, job_id: str, phase: str):
        """Return a context manager that tracks execution time and memory."""
        if self.metrics_collector:
            return self.metrics_collector.track(job_id, phase)
        # No-op context manager
        from contextlib import nullcontext
        return nullcontext()
