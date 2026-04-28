"""
Tests for the Audit Log System (Phase 3).
Run with: python -m pytest tests/test_audit.py -v
"""

import time

import pytest

from core.audit.logger import AuditLogger


class TestAuditLogger:
    """Tests for the structured audit trail."""

    @pytest.fixture
    def audit(self, tmp_path) -> AuditLogger:
        return AuditLogger(str(tmp_path / "test_audit.db"))

    def test_log_action(self, audit):
        """Basic action logging returns a valid row ID."""
        log_id = audit.log_action(
            job_id="test-job-1",
            action="correlation",
            tool="correlate_artifacts",
            command="Running correlation",
        )
        assert log_id > 0

    def test_get_audit_trail(self, audit):
        """Audit trail returns all actions for a job."""
        audit.log_action("job-1", "step_1", "tool_a", "cmd_1")
        audit.log_action("job-1", "step_2", "tool_b", "cmd_2")
        audit.log_action("job-2", "step_1", "tool_a", "cmd_1")  # Different job

        trail = audit.get_audit_trail("job-1")
        assert len(trail) == 2
        assert trail[0]["action"] == "step_1"
        assert trail[1]["action"] == "step_2"

    def test_audit_trail_ordering(self, audit):
        """Entries are returned in chronological order (oldest first)."""
        audit.log_action("job-1", "first", "t", "c")
        audit.log_action("job-1", "second", "t", "c")
        audit.log_action("job-1", "third", "t", "c")

        trail = audit.get_audit_trail("job-1")
        actions = [e["action"] for e in trail]
        assert actions == ["first", "second", "third"]

    def test_error_logging(self, audit):
        """Error status and message are recorded."""
        audit.log_action(
            job_id="job-1",
            action="parse",
            tool="parser",
            command="Parsing pslist",
            status="error",
            error="File not found",
        )

        trail = audit.get_audit_trail("job-1")
        assert len(trail) == 1
        assert trail[0]["status"] == "error"
        assert trail[0]["error"] == "File not found"

    def test_complete_action(self, audit):
        """Completing an action updates duration and status."""
        log_id = audit.log_action("job-1", "test", "tool", "cmd", status="running")
        audit.complete_action(log_id, status="ok", duration_ms=42.5)

        trail = audit.get_audit_trail("job-1")
        assert trail[0]["status"] == "ok"
        assert trail[0]["duration_ms"] == 42.5

    def test_context_manager_success(self, audit):
        """Context manager records timing on success."""
        with audit.track("job-1", "test_phase", "test_tool", "cmd"):
            time.sleep(0.01)

        trail = audit.get_audit_trail("job-1")
        assert len(trail) == 1
        assert trail[0]["status"] == "ok"
        assert trail[0]["duration_ms"] > 0

    def test_context_manager_failure(self, audit):
        """Context manager records error on exception."""
        with pytest.raises(ValueError):
            with audit.track("job-1", "fail_phase", "test_tool", "cmd"):
                raise ValueError("test error")

        trail = audit.get_audit_trail("job-1")
        assert len(trail) == 1
        assert trail[0]["status"] == "error"
        assert "test error" in trail[0]["error"]

    def test_get_all_actions(self, audit):
        """get_all_actions returns recent entries across jobs."""
        audit.log_action("job-1", "a1", "", "")
        audit.log_action("job-2", "a2", "", "")

        all_actions = audit.get_all_actions(limit=10)
        assert len(all_actions) == 2

    def test_metadata_storage(self, audit):
        """Metadata dict is serialized and retrieved correctly."""
        audit.log_action(
            "job-1", "test", "t", "c",
            metadata={"key": "value", "count": 42},
        )

        trail = audit.get_audit_trail("job-1")
        assert trail[0]["metadata"] == {"key": "value", "count": 42}

    def test_empty_trail(self, audit):
        """Empty job returns empty trail."""
        trail = audit.get_audit_trail("nonexistent-job")
        assert trail == []
