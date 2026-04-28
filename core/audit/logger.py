"""
Audit Logger — Structured action trail for reproducibility.
=============================================================
Records every tool execution, command, start/end time, errors,
and metadata for forensic analysis jobs.
"""

import json
import logging
import sqlite3
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Generator, List, Optional

logger = logging.getLogger(__name__)

_DEFAULT_DB_PATH = "C:/Major_Project/core_forensics.db"


class AuditLogger:
    """
    SQLite-backed audit trail for all forensic actions.

    Stores structured log entries per job, including timing,
    tool names, commands, and errors.

    Parameters
    ----------
    db_path : str
        Path to the SQLite database (shared with storage).
    """

    def __init__(self, db_path: str = _DEFAULT_DB_PATH) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._get_conn() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    job_id TEXT NOT NULL,
                    action TEXT NOT NULL,
                    tool TEXT,
                    command TEXT,
                    start_time TEXT NOT NULL,
                    end_time TEXT,
                    duration_ms REAL,
                    status TEXT DEFAULT 'ok',
                    error TEXT,
                    metadata_json TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_audit_job_id
                ON audit_log (job_id)
            """)
            conn.commit()

    # ------------------------------------------------------------------
    # Log actions
    # ------------------------------------------------------------------

    def log_action(
        self,
        job_id: str,
        action: str,
        tool: str = "",
        command: str = "",
        status: str = "ok",
        error: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        duration_ms: Optional[float] = None,
    ) -> int:
        """
        Record a single audit event.

        Parameters
        ----------
        job_id : str
            Associated job ID.
        action : str
            Action name (e.g., ``"correlation"``, ``"cache_check"``).
        tool : str
            Tool or module name.
        command : str
            Human-readable description or command string.
        status : str
            ``"ok"`` or ``"error"``.
        error : str, optional
            Error message if status is ``"error"``.
        metadata : dict, optional
            Additional structured data to store as JSON.
        duration_ms : float, optional
            Execution duration in milliseconds.

        Returns
        -------
        int
            The inserted row ID.
        """
        now = datetime.now(timezone.utc).isoformat()

        with self._get_conn() as conn:
            cursor = conn.execute("""
                INSERT INTO audit_log
                    (job_id, action, tool, command, start_time, end_time,
                     duration_ms, status, error, metadata_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                job_id,
                action,
                tool,
                command,
                now,
                now,
                duration_ms,
                status,
                error,
                json.dumps(metadata, default=str) if metadata else None,
            ))
            conn.commit()
            return cursor.lastrowid

    def complete_action(
        self,
        log_id: int,
        status: str = "ok",
        error: Optional[str] = None,
        duration_ms: Optional[float] = None,
    ) -> None:
        """Update an existing log entry with completion data."""
        now = datetime.now(timezone.utc).isoformat()

        with self._get_conn() as conn:
            conn.execute("""
                UPDATE audit_log
                SET end_time = ?, duration_ms = ?, status = ?, error = ?
                WHERE id = ?
            """, (now, duration_ms, status, error, log_id))
            conn.commit()

    # ------------------------------------------------------------------
    # Context manager for timed blocks
    # ------------------------------------------------------------------

    @contextmanager
    def track(
        self,
        job_id: str,
        action: str,
        tool: str = "",
        command: str = "",
    ) -> Generator[None, None, None]:
        """
        Context manager that auto-records timing for a code block.

        Usage::

            with audit.track(job_id, "correlation", "correlate_artifacts"):
                result = correlate_artifacts(...)

        Records start time on entry, end time + duration on exit.
        If an exception occurs, it records the error before re-raising.
        """
        start = time.perf_counter()
        log_id = self.log_action(
            job_id=job_id,
            action=action,
            tool=tool,
            command=command,
            status="running",
        )

        try:
            yield
            elapsed = (time.perf_counter() - start) * 1000
            self.complete_action(log_id, status="ok", duration_ms=elapsed)
        except Exception as e:
            elapsed = (time.perf_counter() - start) * 1000
            self.complete_action(
                log_id, status="error", error=str(e), duration_ms=elapsed
            )
            raise

    # ------------------------------------------------------------------
    # Query
    # ------------------------------------------------------------------

    def get_audit_trail(self, job_id: str) -> List[Dict[str, Any]]:
        """
        Retrieve the full audit trail for a job.

        Parameters
        ----------
        job_id : str
            Target job ID.

        Returns
        -------
        list[dict]
            Ordered list of audit entries (oldest first).
        """
        with self._get_conn() as conn:
            cursor = conn.execute("""
                SELECT id, job_id, action, tool, command,
                       start_time, end_time, duration_ms,
                       status, error, metadata_json
                FROM audit_log
                WHERE job_id = ?
                ORDER BY id ASC
            """, (job_id,))

            results = []
            for row in cursor.fetchall():
                entry = dict(row)
                # Parse metadata JSON
                if entry.get("metadata_json"):
                    try:
                        entry["metadata"] = json.loads(entry["metadata_json"])
                    except (json.JSONDecodeError, TypeError):
                        entry["metadata"] = None
                else:
                    entry["metadata"] = None
                entry.pop("metadata_json", None)
                results.append(entry)

            return results

    def get_all_actions(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Return recent audit entries across all jobs."""
        with self._get_conn() as conn:
            cursor = conn.execute("""
                SELECT id, job_id, action, tool, command,
                       start_time, end_time, duration_ms, status, error
                FROM audit_log
                ORDER BY id DESC
                LIMIT ?
            """, (limit,))
            return [dict(row) for row in cursor.fetchall()]
