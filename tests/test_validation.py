"""
Tests for the Data Validation Layer (Phase 4).
Run with: python -m pytest tests/test_validation.py -v
"""

import pandas as pd
import pytest

from core.validation.validators import DataValidator, ValidationResult


@pytest.fixture
def validator() -> DataValidator:
    return DataValidator()


# ---------------------------------------------------------------------------
# Schema validation
# ---------------------------------------------------------------------------

class TestPslistValidation:
    """Tests for pslist schema validation."""

    def test_valid_pslist(self, validator):
        """Valid pslist passes validation."""
        df = pd.DataFrame({
            "PID": [1000, 2000],
            "PPID": [500, 1000],
            "ImageFileName": ["explorer.exe", "cmd.exe"],
        })
        result = validator.validate_pslist(df)
        assert result.valid is True
        assert result.errors == []

    def test_missing_columns(self, validator):
        """Missing required columns fails validation."""
        df = pd.DataFrame({"PID": [1000], "ImageFileName": ["test.exe"]})
        result = validator.validate_pslist(df)
        assert result.valid is False
        assert any("PPID" in e for e in result.errors)

    def test_empty_pslist(self, validator):
        """Empty pslist produces a warning, not an error."""
        result = validator.validate_pslist(pd.DataFrame())
        assert result.valid is True
        assert len(result.warnings) > 0

    def test_none_pslist(self, validator):
        """None pslist produces a warning."""
        result = validator.validate_pslist(None)
        assert result.valid is True
        assert len(result.warnings) > 0

    def test_empty_image_names(self, validator):
        """Empty ImageFileName values produce warnings."""
        df = pd.DataFrame({
            "PID": [1000, 2000],
            "PPID": [500, 1000],
            "ImageFileName": ["explorer.exe", ""],
        })
        result = validator.validate_pslist(df)
        assert result.valid is True
        assert any("empty ImageFileName" in w for w in result.warnings)


class TestNetscanValidation:
    """Tests for netscan schema validation."""

    def test_valid_netscan(self, validator):
        """Valid netscan passes validation."""
        df = pd.DataFrame({
            "PID": [1000],
            "ForeignAddr": ["8.8.8.8"],
            "State": ["ESTABLISHED"],
        })
        result = validator.validate_netscan(df)
        assert result.valid is True

    def test_missing_pid(self, validator):
        """Missing PID column fails validation."""
        df = pd.DataFrame({"ForeignAddr": ["8.8.8.8"]})
        result = validator.validate_netscan(df)
        assert result.valid is False

    def test_empty_netscan(self, validator):
        """Empty netscan produces a warning."""
        result = validator.validate_netscan(pd.DataFrame())
        assert result.valid is True


class TestMalfindValidation:
    """Tests for malfind schema validation."""

    def test_valid_malfind(self, validator):
        """Valid malfind passes validation."""
        df = pd.DataFrame({
            "PID": [1000],
            "Process": ["powershell.exe"],
            "Protection": ["PAGE_EXECUTE_READWRITE"],
        })
        result = validator.validate_malfind(df)
        assert result.valid is True

    def test_missing_pid(self, validator):
        """Missing PID column fails validation."""
        df = pd.DataFrame({"Process": ["test.exe"]})
        result = validator.validate_malfind(df)
        assert result.valid is False


# ---------------------------------------------------------------------------
# Sanity checks
# ---------------------------------------------------------------------------

class TestPidConsistency:
    """Tests for PID consistency checks."""

    def test_consistent_pids(self, validator):
        """No warnings when all net PIDs exist in pslist."""
        ps = pd.DataFrame({"PID": [1000, 2000, 3000]})
        net = pd.DataFrame({"PID": [1000, 2000]})
        warnings = validator.check_pid_consistency(ps, net)
        assert warnings == []

    def test_orphaned_pids(self, validator):
        """Warns about PIDs in netscan not found in pslist."""
        ps = pd.DataFrame({"PID": [1000]})
        net = pd.DataFrame({"PID": [1000, 9999]})
        warnings = validator.check_pid_consistency(ps, net)
        assert len(warnings) == 1
        assert "9999" in warnings[0]

    def test_empty_inputs(self, validator):
        """Empty inputs produce no warnings."""
        assert validator.check_pid_consistency(pd.DataFrame(), pd.DataFrame()) == []


class TestTimestampValidity:
    """Tests for timestamp validation."""

    def test_valid_timestamps(self, validator):
        """Valid timestamps produce no warnings."""
        df = pd.DataFrame({
            "CreateTime": ["2026-04-10 10:00:00", "2026-04-10 11:00:00"]
        })
        warnings = validator.check_timestamp_validity(df, "CreateTime")
        assert warnings == []

    def test_unparseable_timestamps(self, validator):
        """Unparseable timestamps produce warnings."""
        df = pd.DataFrame({
            "CreateTime": ["not-a-date", "2026-04-10 10:00:00"]
        })
        warnings = validator.check_timestamp_validity(df, "CreateTime")
        assert any("unparseable" in w for w in warnings)

    def test_ancient_timestamps(self, validator):
        """Timestamps before year 2000 produce warnings."""
        df = pd.DataFrame({
            "CreateTime": ["1990-01-01 00:00:00"]
        })
        warnings = validator.check_timestamp_validity(df, "CreateTime")
        assert any("before year 2000" in w for w in warnings)

    def test_missing_column(self, validator):
        """Missing column produces no warnings."""
        df = pd.DataFrame({"Other": [1, 2]})
        assert validator.check_timestamp_validity(df, "CreateTime") == []


class TestDuplicatePids:
    """Tests for duplicate PID detection."""

    def test_no_duplicates(self, validator):
        """Unique PIDs produce no warnings."""
        df = pd.DataFrame({"PID": [1000, 2000, 3000]})
        assert validator.check_duplicate_pids(df) == []

    def test_with_duplicates(self, validator):
        """Duplicate PIDs produce a warning."""
        df = pd.DataFrame({"PID": [1000, 2000, 1000]})
        warnings = validator.check_duplicate_pids(df)
        assert len(warnings) == 1
        assert "1000" in warnings[0]

    def test_empty_df(self, validator):
        """Empty DataFrame produces no warnings."""
        assert validator.check_duplicate_pids(pd.DataFrame()) == []


# ---------------------------------------------------------------------------
# Performance
# ---------------------------------------------------------------------------

class TestValidationPerformance:
    """Verify validation scales to large datasets."""

    def test_large_pslist_validation(self, validator):
        """100k row pslist validates in under 2 seconds."""
        import time
        n = 100_000
        df = pd.DataFrame({
            "PID": range(n),
            "PPID": [max(0, i - 1) for i in range(n)],
            "ImageFileName": ["svchost.exe"] * n,
        })
        start = time.time()
        result = validator.validate_pslist(df)
        elapsed = time.time() - start
        assert result.valid is True
        assert elapsed < 2.0, f"Took {elapsed:.2f}s — too slow"
