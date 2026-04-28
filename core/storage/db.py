"""
Storage Database — SQLite backend for cached analysis results.
================================================================
Stores serialized correlation, timeline, graph, and alert data
keyed by the SHA256 hash of the memory dump.
"""

import json
import logging
import sqlite3
from pathlib import Path
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

_DEFAULT_DB_PATH = "C:/Major_Project/core_forensics.db"


class StorageDatabase:
    """SQLite backend for analysis result caching."""

    def __init__(self, db_path: str = _DEFAULT_DB_PATH) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")  # Better concurrent reads
        return conn

    def _init_db(self) -> None:
        with self._get_conn() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS analysis_cache (
                    dump_hash TEXT PRIMARY KEY,
                    dump_path TEXT NOT NULL,
                    correlation_json TEXT,
                    timeline_json TEXT,
                    graph_json TEXT,
                    alerts_json TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.commit()

    # ------------------------------------------------------------------
    # CRUD
    # ------------------------------------------------------------------

    def has_result(self, dump_hash: str) -> bool:
        """Check if a cached result exists for the given dump hash."""
        with self._get_conn() as conn:
            cursor = conn.execute(
                "SELECT 1 FROM analysis_cache WHERE dump_hash = ?", (dump_hash,)
            )
            return cursor.fetchone() is not None

    def get_result(self, dump_hash: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve cached analysis results.

        Returns
        -------
        dict or None
            Keys: ``correlation``, ``timeline``, ``graph``, ``alerts``.
        """
        with self._get_conn() as conn:
            cursor = conn.execute(
                "SELECT * FROM analysis_cache WHERE dump_hash = ?", (dump_hash,)
            )
            row = cursor.fetchone()
            if row is None:
                return None

            return {
                "dump_hash": row["dump_hash"],
                "dump_path": row["dump_path"],
                "correlation": self._safe_json_load(row["correlation_json"]),
                "timeline": self._safe_json_load(row["timeline_json"]),
                "graph": self._safe_json_load(row["graph_json"]),
                "alerts": self._safe_json_load(row["alerts_json"]),
                "created_at": row["created_at"],
            }

    def save_result(
        self,
        dump_hash: str,
        dump_path: str,
        results: Dict[str, Any],
    ) -> None:
        """
        Store analysis results keyed by dump hash.

        Parameters
        ----------
        dump_hash : str
            SHA256 hex digest of the memory dump.
        dump_path : str
            Original file path.
        results : dict
            Keys: ``correlation``, ``timeline``, ``graph``, ``alerts``.
        """
        with self._get_conn() as conn:
            conn.execute("""
                INSERT OR REPLACE INTO analysis_cache
                    (dump_hash, dump_path, correlation_json, timeline_json, graph_json, alerts_json)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                dump_hash,
                dump_path,
                json.dumps(results.get("correlation"), default=str),
                json.dumps(results.get("timeline"), default=str),
                json.dumps(results.get("graph"), default=str),
                json.dumps(results.get("alerts"), default=str),
            ))
            conn.commit()
        logger.info(f"Cached result for hash {dump_hash[:16]}...")

    def invalidate(self, dump_hash: str) -> None:
        """Remove a cached result."""
        with self._get_conn() as conn:
            conn.execute(
                "DELETE FROM analysis_cache WHERE dump_hash = ?", (dump_hash,)
            )
            conn.commit()
        logger.info(f"Invalidated cache for hash {dump_hash[:16]}...")

    def list_cached(self) -> list:
        """List all cached dump hashes and paths."""
        with self._get_conn() as conn:
            cursor = conn.execute(
                "SELECT dump_hash, dump_path, created_at FROM analysis_cache ORDER BY created_at DESC"
            )
            return [dict(row) for row in cursor.fetchall()]

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _safe_json_load(data: Optional[str]) -> Any:
        if data is None:
            return None
        try:
            return json.loads(data)
        except (json.JSONDecodeError, TypeError):
            return None
