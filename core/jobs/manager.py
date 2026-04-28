"""
Job Manager — Thread-safe job lifecycle management.
=====================================================
Provides create/update/query operations for forensic analysis jobs.
All state mutations are protected by a threading lock.
"""

import logging
import threading
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional

from .models import JobInfo, JobResult, JobStatus

logger = logging.getLogger(__name__)


class JobManager:
    """Thread-safe in-memory job store."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._jobs: Dict[str, JobInfo] = {}
        self._results: Dict[str, JobResult] = {}

    # ------------------------------------------------------------------
    # Create
    # ------------------------------------------------------------------

    def create_job(self, dump_path: str, job_type: str = "single") -> str:
        """
        Register a new job and return its UUID.

        Parameters
        ----------
        dump_path : str
            Path to the memory dump file (or comma-separated for multi).
        job_type : str
            ``"single"`` or ``"multi"``.

        Returns
        -------
        str
            The newly created job ID (UUID4).
        """
        job_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()

        info = JobInfo(
            job_id=job_id,
            status=JobStatus.QUEUED,
            progress=0,
            result_available=False,
            created_at=now,
            dump_path=dump_path,
            job_type=job_type,
        )

        with self._lock:
            self._jobs[job_id] = info

        logger.info(f"Job created: {job_id} ({job_type}) for {dump_path}")
        return job_id

    # ------------------------------------------------------------------
    # Update
    # ------------------------------------------------------------------

    def update_status(
        self,
        job_id: str,
        status: Optional[JobStatus] = None,
        progress: Optional[int] = None,
        error: Optional[str] = None,
        dump_hash: Optional[str] = None,
    ) -> None:
        """
        Thread-safe status update.

        Parameters
        ----------
        job_id : str
            Target job.
        status : JobStatus, optional
            New status value.
        progress : int, optional
            Progress percentage (0-100).
        error : str, optional
            Error message if ``status == FAILED``.
        dump_hash : str, optional
            SHA256 hash of the dump (set once computed).
        """
        with self._lock:
            info = self._jobs.get(job_id)
            if info is None:
                logger.warning(f"update_status called for unknown job {job_id}")
                return

            if status is not None:
                info.status = status
            if progress is not None:
                info.progress = max(0, min(100, progress))
            if error is not None:
                info.error = error
            if dump_hash is not None:
                info.dump_hash = dump_hash

            if status in (JobStatus.COMPLETED, JobStatus.FAILED):
                info.completed_at = datetime.now(timezone.utc).isoformat()

            if status == JobStatus.COMPLETED:
                info.result_available = True

    # ------------------------------------------------------------------
    # Store / retrieve results
    # ------------------------------------------------------------------

    def store_result(self, job_id: str, result: JobResult) -> None:
        """Persist analysis results for a completed job."""
        with self._lock:
            self._results[job_id] = result

    def get_result(self, job_id: str) -> Optional[JobResult]:
        """Retrieve analysis results (returns None if not yet available)."""
        with self._lock:
            return self._results.get(job_id)

    # ------------------------------------------------------------------
    # Query
    # ------------------------------------------------------------------

    def get_status(self, job_id: str) -> Optional[JobInfo]:
        """Return current job info or ``None`` if the job doesn't exist."""
        with self._lock:
            return self._jobs.get(job_id)

    def list_jobs(self) -> List[JobInfo]:
        """Return a snapshot of all known jobs (newest first)."""
        with self._lock:
            jobs = list(self._jobs.values())
        return sorted(jobs, key=lambda j: j.created_at, reverse=True)

    def job_exists(self, job_id: str) -> bool:
        """Check whether a job ID is registered."""
        with self._lock:
            return job_id in self._jobs
