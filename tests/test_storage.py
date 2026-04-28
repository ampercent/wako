"""
Tests for the Result Storage and Caching System (Phase 2).
Run with: python -m pytest tests/test_storage.py -v
"""

import os
import tempfile

import pytest

from core.storage.cache import CacheManager
from core.storage.db import StorageDatabase


# ---------------------------------------------------------------------------
# StorageDatabase tests
# ---------------------------------------------------------------------------

class TestStorageDatabase:
    """Tests for the SQLite storage backend."""

    @pytest.fixture
    def db(self, tmp_path) -> StorageDatabase:
        return StorageDatabase(str(tmp_path / "test.db"))

    def test_init_creates_table(self, db):
        """Database initialization creates the analysis_cache table."""
        assert db.db_path.exists()

    def test_save_and_get_result(self, db):
        """Results can be saved and retrieved by hash."""
        db.save_result("abc123", "/test/dump.dmp", {
            "correlation": [{"PID": 1000}],
            "timeline": [{"event": "test"}],
            "graph": {"nodes": []},
            "alerts": [],
        })

        result = db.get_result("abc123")
        assert result is not None
        assert result["dump_hash"] == "abc123"
        assert result["correlation"] == [{"PID": 1000}]
        assert result["graph"] == {"nodes": []}

    def test_has_result(self, db):
        """has_result returns correct boolean."""
        assert db.has_result("abc123") is False
        db.save_result("abc123", "/test/dump.dmp", {"correlation": []})
        assert db.has_result("abc123") is True

    def test_get_nonexistent(self, db):
        """Getting a nonexistent hash returns None."""
        assert db.get_result("nonexistent") is None

    def test_invalidate(self, db):
        """Invalidating a cached result removes it."""
        db.save_result("abc123", "/test/dump.dmp", {"correlation": []})
        assert db.has_result("abc123") is True
        db.invalidate("abc123")
        assert db.has_result("abc123") is False

    def test_overwrite_on_save(self, db):
        """Saving with the same hash overwrites the existing entry."""
        db.save_result("abc123", "/test/old.dmp", {"correlation": [{"old": True}]})
        db.save_result("abc123", "/test/new.dmp", {"correlation": [{"new": True}]})

        result = db.get_result("abc123")
        assert result["dump_path"] == "/test/new.dmp"
        assert result["correlation"] == [{"new": True}]

    def test_list_cached(self, db):
        """List returns all cached entries."""
        db.save_result("hash1", "/a.dmp", {"correlation": []})
        db.save_result("hash2", "/b.dmp", {"correlation": []})

        cached = db.list_cached()
        assert len(cached) == 2


# ---------------------------------------------------------------------------
# CacheManager tests
# ---------------------------------------------------------------------------

class TestCacheManager:
    """Tests for the high-level cache manager."""

    @pytest.fixture
    def cache(self, tmp_path) -> CacheManager:
        return CacheManager(str(tmp_path / "test_cache.db"))

    def test_compute_hash_nonexistent_file(self, cache):
        """Hashing a nonexistent path returns a path-based hash."""
        h = cache.compute_dump_hash("/nonexistent/file.dmp")
        assert len(h) == 64  # SHA256 hex digest length

    def test_compute_hash_real_file(self, cache, tmp_path):
        """Hashing a real file returns consistent SHA256."""
        test_file = tmp_path / "test_dump.bin"
        test_file.write_bytes(b"test data content")

        h1 = cache.compute_dump_hash(str(test_file))
        h2 = cache.compute_dump_hash(str(test_file))

        assert h1 == h2
        assert len(h1) == 64

    def test_compute_hash_different_content(self, cache, tmp_path):
        """Different files produce different hashes."""
        file_a = tmp_path / "a.bin"
        file_b = tmp_path / "b.bin"
        file_a.write_bytes(b"content A")
        file_b.write_bytes(b"content B")

        assert cache.compute_dump_hash(str(file_a)) != cache.compute_dump_hash(str(file_b))

    def test_cache_check_miss(self, cache):
        """Cache check for new dump returns miss."""
        hit, result, hash_val = cache.check_cache("/test/new.dmp")
        assert hit is False
        assert result is None
        assert len(hash_val) == 64

    def test_cache_store_and_check_hit(self, cache):
        """Storing then checking returns a hit."""
        cache.store_cache("/test/dump.dmp", {
            "correlation": [{"PID": 1000}],
            "timeline": [],
        })

        hit, result, hash_val = cache.check_cache("/test/dump.dmp")
        assert hit is True
        assert result is not None
        assert result["correlation"] == [{"PID": 1000}]

    def test_invalidate(self, cache):
        """Invalidating removes cached result."""
        cache.store_cache("/test/dump.dmp", {"correlation": []})
        cache.invalidate("/test/dump.dmp")

        hit, _, _ = cache.check_cache("/test/dump.dmp")
        assert hit is False

    def test_hash_memoization(self, cache):
        """Same path is not rehashed within process."""
        h1 = cache.compute_dump_hash("/test/memo.dmp")
        h2 = cache.compute_dump_hash("/test/memo.dmp")
        assert h1 == h2
        assert "/test/memo.dmp" in cache._hash_cache
