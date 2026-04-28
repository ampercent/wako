"""
Cache Manager — SHA256-keyed result deduplication.
=====================================================
Computes memory dump hashes and orchestrates the StorageDatabase
to avoid recomputing expensive analysis.
"""

import hashlib
import logging
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from .db import StorageDatabase

logger = logging.getLogger(__name__)

# Read files in 64 KB chunks to handle multi-GB dumps
_HASH_CHUNK_SIZE = 65_536


class CacheManager:
    """
    High-level cache interface for forensic analysis results.

    Parameters
    ----------
    db_path : str
        Path to the SQLite database file.
    """

    def __init__(self, db_path: str = "C:/Major_Project/core_forensics.db") -> None:
        self.db = StorageDatabase(db_path)
        self._hash_cache: Dict[str, str] = {}  # path → hash memo

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def check_cache(self, dump_path: str) -> Tuple[bool, Optional[Dict[str, Any]], str]:
        """
        Check if results for a dump file are already cached.

        Parameters
        ----------
        dump_path : str
            Path to the memory dump.

        Returns
        -------
        (hit, result, dump_hash)
            ``hit`` is True if cache contains results.
            ``result`` is the cached data dict (or None on miss).
            ``dump_hash`` is the SHA256 hex digest.
        """
        dump_hash = self.compute_dump_hash(dump_path)

        if self.db.has_result(dump_hash):
            result = self.db.get_result(dump_hash)
            return True, result, dump_hash
        return False, None, dump_hash

    def store_cache(self, dump_path: str, results: Dict[str, Any]) -> str:
        """
        Cache results for a dump file.

        Parameters
        ----------
        dump_path : str
            Path to the memory dump.
        results : dict
            Analysis results to store.

        Returns
        -------
        str
            The SHA256 hash used as the cache key.
        """
        dump_hash = self.compute_dump_hash(dump_path)
        self.db.save_result(dump_hash, dump_path, results)
        return dump_hash

    def store_cache_from_hash(
        self, dump_hash: str, dump_path: str, results: Dict[str, Any]
    ) -> None:
        """Store results when the hash is already known (avoids rehashing)."""
        self.db.save_result(dump_hash, dump_path, results)

    def invalidate(self, dump_path: str) -> None:
        """Remove cached results for a specific dump."""
        dump_hash = self.compute_dump_hash(dump_path)
        self.db.invalidate(dump_hash)
        self._hash_cache.pop(dump_path, None)

    def list_cached(self) -> list:
        """Return a list of all cached entries."""
        return self.db.list_cached()

    # ------------------------------------------------------------------
    # Hashing
    # ------------------------------------------------------------------

    def compute_dump_hash(self, dump_path: str) -> str:
        """
        Compute SHA256 hash of a file, reading in chunks.

        Uses an internal memo dict to avoid rehashing the same path
        within a single process lifetime.

        Parameters
        ----------
        dump_path : str
            Path to the file.

        Returns
        -------
        str
            Hex digest of the SHA256 hash.
        """
        # Memo check
        if dump_path in self._hash_cache:
            return self._hash_cache[dump_path]

        path = Path(dump_path)
        if not path.exists():
            # For non-existent files (e.g., test/mock paths), use path hash
            digest = hashlib.sha256(dump_path.encode()).hexdigest()
            self._hash_cache[dump_path] = digest
            return digest

        sha = hashlib.sha256()
        with open(path, "rb") as f:
            while True:
                chunk = f.read(_HASH_CHUNK_SIZE)
                if not chunk:
                    break
                sha.update(chunk)

        digest = sha.hexdigest()
        self._hash_cache[dump_path] = digest
        logger.info(f"Computed SHA256 for {path.name}: {digest[:16]}...")
        return digest
