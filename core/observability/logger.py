"""
Observability — Structured Request Logging
============================================
JSON structured logging for all API requests with request_id,
user_id, timing, result counts, and error tracking.
"""

import json
import logging
import time
import uuid
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Generator, Optional


@dataclass
class RequestLog:
    """Structured log entry for a single API request."""
    request_id: str
    endpoint: str
    method: str
    user_id: Optional[int] = None
    username: Optional[str] = None
    query_length: Optional[int] = None
    result_count: Optional[int] = None
    execution_time_ms: float = 0.0
    status_code: int = 200
    error: Optional[str] = None
    truncated: bool = False
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    extra: dict = field(default_factory=dict)


class RequestLogger:
    """
    Structured JSON logger for API request observability.
    
    Emits one JSON line per request to both Python's logging
    system and an in-memory ring buffer for the /logs endpoint.
    
    Parameters
    ----------
    buffer_size : int
        Maximum number of log entries kept in the ring buffer.
    """

    def __init__(self, buffer_size: int = 1000) -> None:
        self._logger = logging.getLogger("antigravity.requests")
        self._buffer: list[RequestLog] = []
        self._buffer_size = buffer_size

        # Ensure JSON handler exists
        if not self._logger.handlers:
            handler = logging.StreamHandler()
            handler.setFormatter(logging.Formatter("%(message)s"))
            self._logger.addHandler(handler)
            self._logger.setLevel(logging.INFO)

    def log(self, entry: RequestLog) -> None:
        """Emit a structured log entry."""
        data = asdict(entry)
        # Remove None values for cleaner logs
        data = {k: v for k, v in data.items() if v is not None}
        self._logger.info(json.dumps(data, default=str))
        self._buffer.append(entry)
        # Trim ring buffer
        if len(self._buffer) > self._buffer_size:
            self._buffer = self._buffer[-self._buffer_size:]

    @contextmanager
    def track_request(
        self,
        endpoint: str,
        method: str = "POST",
        user: Optional[dict] = None,
    ) -> Generator[RequestLog, None, None]:
        """
        Context manager that auto-tracks execution time.
        
        Usage::
        
            with request_logger.track_request("/hunt/query", user=current_user) as log:
                results = engine.execute(query)
                log.result_count = len(results)
                log.query_length = len(query)
        """
        entry = RequestLog(
            request_id=str(uuid.uuid4()),
            endpoint=endpoint,
            method=method,
            user_id=user.get("id") if user else None,
            username=user.get("username") if user else None,
        )
        start = time.perf_counter()

        try:
            yield entry
        except Exception as exc:
            entry.error = str(exc)[:200]  # Truncate for safety
            entry.status_code = 500
            raise
        finally:
            entry.execution_time_ms = round((time.perf_counter() - start) * 1000, 2)
            self.log(entry)

    def get_recent(self, limit: int = 100) -> list[dict]:
        """Return the most recent log entries as dicts."""
        entries = self._buffer[-limit:]
        return [asdict(e) for e in reversed(entries)]

    def get_error_logs(self, limit: int = 50) -> list[dict]:
        """Return recent entries with errors."""
        errors = [e for e in self._buffer if e.error]
        return [asdict(e) for e in errors[-limit:]]
