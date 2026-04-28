"""
Tests for the Async Job System (Phase 1).
Run with: python -m pytest tests/test_jobs.py -v
"""

import time
import pytest
from core.jobs.models import JobStatus, JobInfo, JobResult, AnalyzeRequest
from core.jobs.manager import JobManager
from core.jobs.worker import JobWorker


# ---------------------------------------------------------------------------
# JobManager tests
# ---------------------------------------------------------------------------

class TestJobManager:
    """Tests for JobManager lifecycle operations."""

    def test_create_job(self):
        """Creating a job returns a UUID and registers it."""
        mgr = JobManager()
        job_id = mgr.create_job("/test/dump.dmp")
        assert job_id is not None
        assert len(job_id) == 36  # UUID format

    def test_get_status(self):
        """Newly created job should be QUEUED with 0 progress."""
        mgr = JobManager()
        job_id = mgr.create_job("/test/dump.dmp")
        info = mgr.get_status(job_id)
        assert info is not None
        assert info.status == JobStatus.QUEUED
        assert info.progress == 0
        assert info.result_available is False

    def test_update_status(self):
        """Status updates are reflected correctly."""
        mgr = JobManager()
        job_id = mgr.create_job("/test/dump.dmp")

        mgr.update_status(job_id, status=JobStatus.RUNNING, progress=50)
        info = mgr.get_status(job_id)
        assert info.status == JobStatus.RUNNING
        assert info.progress == 50

    def test_complete_job(self):
        """Completing a job sets result_available and completed_at."""
        mgr = JobManager()
        job_id = mgr.create_job("/test/dump.dmp")

        mgr.update_status(job_id, status=JobStatus.COMPLETED, progress=100)
        info = mgr.get_status(job_id)
        assert info.status == JobStatus.COMPLETED
        assert info.result_available is True
        assert info.completed_at is not None

    def test_fail_job(self):
        """Failing a job records the error message."""
        mgr = JobManager()
        job_id = mgr.create_job("/test/dump.dmp")

        mgr.update_status(job_id, status=JobStatus.FAILED, error="Test error")
        info = mgr.get_status(job_id)
        assert info.status == JobStatus.FAILED
        assert info.error == "Test error"
        assert info.completed_at is not None

    def test_store_and_get_result(self):
        """Results can be stored and retrieved."""
        mgr = JobManager()
        job_id = mgr.create_job("/test/dump.dmp")

        result = JobResult(
            correlation=[{"PID": 1000}],
            timeline=[{"event": "test"}],
            graph={"nodes": [], "edges": []},
            alerts=[],
        )
        mgr.store_result(job_id, result)
        retrieved = mgr.get_result(job_id)
        assert retrieved is not None
        assert retrieved.correlation == [{"PID": 1000}]

    def test_list_jobs(self):
        """All created jobs appear in the list."""
        mgr = JobManager()
        mgr.create_job("/test/a.dmp")
        mgr.create_job("/test/b.dmp")
        mgr.create_job("/test/c.dmp")

        jobs = mgr.list_jobs()
        assert len(jobs) == 3

    def test_nonexistent_job(self):
        """Querying a non-existent job returns None."""
        mgr = JobManager()
        assert mgr.get_status("fake-id") is None
        assert mgr.get_result("fake-id") is None

    def test_job_exists(self):
        """job_exists returns correct boolean."""
        mgr = JobManager()
        job_id = mgr.create_job("/test/dump.dmp")
        assert mgr.job_exists(job_id) is True
        assert mgr.job_exists("nonexistent") is False

    def test_progress_clamping(self):
        """Progress is clamped to 0-100 range."""
        mgr = JobManager()
        job_id = mgr.create_job("/test/dump.dmp")

        mgr.update_status(job_id, progress=150)
        assert mgr.get_status(job_id).progress == 100

        mgr.update_status(job_id, progress=-10)
        assert mgr.get_status(job_id).progress == 0

    def test_dump_hash_update(self):
        """Dump hash can be set after creation."""
        mgr = JobManager()
        job_id = mgr.create_job("/test/dump.dmp")
        mgr.update_status(job_id, dump_hash="abc123")
        assert mgr.get_status(job_id).dump_hash == "abc123"


# ---------------------------------------------------------------------------
# JobWorker integration tests
# ---------------------------------------------------------------------------

class TestJobWorker:
    """Integration tests for JobWorker pipeline execution."""

    def test_worker_completes_job(self):
        """Worker runs the full pipeline and marks job complete."""
        mgr = JobManager()
        worker = JobWorker(job_manager=mgr, max_workers=1)

        job_id = mgr.create_job("/test/mock.dmp")
        worker.submit(job_id, "/test/mock.dmp")

        # Wait for completion (up to 15 seconds)
        for _ in range(30):
            info = mgr.get_status(job_id)
            if info.status in (JobStatus.COMPLETED, JobStatus.FAILED):
                break
            time.sleep(0.5)

        info = mgr.get_status(job_id)
        assert info.status == JobStatus.COMPLETED
        assert info.progress == 100
        assert info.result_available is True

        result = mgr.get_result(job_id)
        assert result is not None
        assert result.correlation is not None
        assert result.timeline is not None
        assert result.graph is not None

        worker.shutdown()

    def test_worker_job_status_progression(self):
        """Job status progresses through queued → running → completed."""
        mgr = JobManager()
        worker = JobWorker(job_manager=mgr, max_workers=1)

        job_id = mgr.create_job("/test/mock.dmp")

        # Initially queued
        assert mgr.get_status(job_id).status == JobStatus.QUEUED

        worker.submit(job_id, "/test/mock.dmp")

        # Wait for completion
        for _ in range(30):
            info = mgr.get_status(job_id)
            if info.status == JobStatus.COMPLETED:
                break
            time.sleep(0.5)

        assert mgr.get_status(job_id).status == JobStatus.COMPLETED
        worker.shutdown()


# ---------------------------------------------------------------------------
# Model tests
# ---------------------------------------------------------------------------

class TestModels:
    """Tests for Pydantic models."""

    def test_analyze_request(self):
        """AnalyzeRequest accepts a valid dump_path."""
        req = AnalyzeRequest(dump_path="/test/dump.dmp")
        assert req.dump_path == "/test/dump.dmp"

    def test_job_status_enum(self):
        """JobStatus values are correct strings."""
        assert JobStatus.QUEUED.value == "queued"
        assert JobStatus.RUNNING.value == "running"
        assert JobStatus.COMPLETED.value == "completed"
        assert JobStatus.FAILED.value == "failed"

    def test_job_result_defaults(self):
        """JobResult defaults are None/False."""
        result = JobResult()
        assert result.correlation is None
        assert result.cached is False
