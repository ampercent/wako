"""
Tests for Multi-Dump Analysis (Phase 6).
Run with: python -m pytest tests/test_multi_dump.py -v
"""

import pandas as pd
import pytest

from diff_analysis.analyzer import DiffAnalyzer


@pytest.fixture
def analyzer() -> DiffAnalyzer:
    return DiffAnalyzer()


# ---------------------------------------------------------------------------
# merge_timelines
# ---------------------------------------------------------------------------

class TestMergeTimelines:
    """Tests for timeline merging."""

    def test_basic_merge(self, analyzer):
        """Two timelines merge with source labels."""
        tl_a = pd.DataFrame({
            "timestamp": pd.to_datetime(["2026-04-10 10:00:00", "2026-04-10 10:05:00"]),
            "event_type": ["process_start", "network_connect"],
            "pid": [1000, 1000],
        })
        tl_b = pd.DataFrame({
            "timestamp": pd.to_datetime(["2026-04-10 10:02:00", "2026-04-10 10:07:00"]),
            "event_type": ["process_start", "injection"],
            "pid": [2000, 2000],
        })

        merged = analyzer.merge_timelines(tl_a, tl_b)
        assert len(merged) == 4
        assert "source" in merged.columns
        assert set(merged["source"].unique()) == {"dump_A", "dump_B"}

    def test_chronological_order(self, analyzer):
        """Merged timeline is sorted by timestamp."""
        tl_a = pd.DataFrame({
            "timestamp": pd.to_datetime(["2026-04-10 10:05:00"]),
            "pid": [1000],
        })
        tl_b = pd.DataFrame({
            "timestamp": pd.to_datetime(["2026-04-10 10:00:00"]),
            "pid": [2000],
        })

        merged = analyzer.merge_timelines(tl_a, tl_b)
        # dump_B event should come first (earlier timestamp)
        assert merged.iloc[0]["pid"] == 2000

    def test_custom_labels(self, analyzer):
        """Custom source labels are applied."""
        tl_a = pd.DataFrame({"timestamp": ["2026-04-10"], "pid": [1]})
        tl_b = pd.DataFrame({"timestamp": ["2026-04-10"], "pid": [2]})

        merged = analyzer.merge_timelines(tl_a, tl_b, label_a="baseline", label_b="suspect")
        assert set(merged["source"].unique()) == {"baseline", "suspect"}

    def test_empty_timeline(self, analyzer):
        """Merging with empty DataFrame returns non-empty result."""
        tl = pd.DataFrame({"timestamp": ["2026-04-10"], "pid": [1]})
        merged = analyzer.merge_timelines(tl, pd.DataFrame())
        assert len(merged) == 1

    def test_both_empty(self, analyzer):
        """Merging two empty DataFrames returns empty."""
        merged = analyzer.merge_timelines(pd.DataFrame(), pd.DataFrame())
        assert merged.empty


# ---------------------------------------------------------------------------
# compare_correlations
# ---------------------------------------------------------------------------

class TestCompareCorrelations:
    """Tests for correlation comparison."""

    def test_new_processes(self, analyzer):
        """Detects new processes in target."""
        corr_a = pd.DataFrame({
            "PID": [1000],
            "ImageFileName": ["explorer.exe"],
            "correlation_score": [0],
        })
        corr_b = pd.DataFrame({
            "PID": [1000, 2000],
            "ImageFileName": ["explorer.exe", "malware.exe"],
            "correlation_score": [0, 8],
        })

        diff = analyzer.compare_correlations(corr_a, corr_b)
        assert len(diff["new_processes"]) == 1
        assert diff["new_processes"][0]["process"] == "malware.exe"

    def test_missing_processes(self, analyzer):
        """Detects missing processes from baseline."""
        corr_a = pd.DataFrame({
            "PID": [1000, 2000],
            "ImageFileName": ["explorer.exe", "svchost.exe"],
            "correlation_score": [0, 0],
        })
        corr_b = pd.DataFrame({
            "PID": [1000],
            "ImageFileName": ["explorer.exe"],
            "correlation_score": [0],
        })

        diff = analyzer.compare_correlations(corr_a, corr_b)
        assert len(diff["missing_processes"]) == 1
        assert diff["missing_processes"][0]["process"] == "svchost.exe"

    def test_score_changes(self, analyzer):
        """Detects score changes for common processes."""
        corr_a = pd.DataFrame({
            "PID": [1000],
            "ImageFileName": ["powershell.exe"],
            "correlation_score": [3],
        })
        corr_b = pd.DataFrame({
            "PID": [1000],
            "ImageFileName": ["powershell.exe"],
            "correlation_score": [8],
        })

        diff = analyzer.compare_correlations(corr_a, corr_b)
        assert len(diff["score_changes"]) == 1
        assert diff["score_changes"][0]["delta"] == 5

    def test_new_flags(self, analyzer):
        """Detects newly set behavioral flags."""
        corr_a = pd.DataFrame({
            "PID": [1000],
            "ImageFileName": ["powershell.exe"],
            "correlation_score": [1],
            "has_network": [False],
            "has_injection": [False],
            "suspicious_parent": [False],
        })
        corr_b = pd.DataFrame({
            "PID": [1000],
            "ImageFileName": ["powershell.exe"],
            "correlation_score": [5],
            "has_network": [True],
            "has_injection": [True],
            "suspicious_parent": [False],
        })

        diff = analyzer.compare_correlations(corr_a, corr_b)
        assert len(diff["new_flags"]) == 2
        flags = {f["flag"] for f in diff["new_flags"]}
        assert flags == {"has_network", "has_injection"}

    def test_empty_inputs(self, analyzer):
        """Empty inputs return empty diff."""
        diff = analyzer.compare_correlations(pd.DataFrame(), pd.DataFrame())
        assert diff["new_processes"] == []
        assert diff["missing_processes"] == []

    def test_identical_corrs(self, analyzer):
        """Identical correlations produce no changes."""
        corr = pd.DataFrame({
            "PID": [1000],
            "ImageFileName": ["explorer.exe"],
            "correlation_score": [0],
        })

        diff = analyzer.compare_correlations(corr, corr.copy())
        assert diff["new_processes"] == []
        assert diff["missing_processes"] == []
        assert diff["score_changes"] == []
        assert diff["new_flags"] == []


# ---------------------------------------------------------------------------
# Existing compare_dumps (backward compatibility)
# ---------------------------------------------------------------------------

class TestCompareDumps:
    """Verify existing compare_dumps still works correctly."""

    def test_new_process_detection(self, analyzer):
        """Detects newly spawned processes."""
        base = pd.DataFrame({"ImageFileName": ["explorer.exe", "svchost.exe"]})
        target = pd.DataFrame({"ImageFileName": ["explorer.exe", "svchost.exe", "malware.exe"]})

        result = analyzer.compare_dumps(base, target, pd.DataFrame(), pd.DataFrame())
        assert "malware.exe" in result["new_processes"]

    def test_missing_process_detection(self, analyzer):
        """Detects missing processes."""
        base = pd.DataFrame({"ImageFileName": ["explorer.exe", "svchost.exe"]})
        target = pd.DataFrame({"ImageFileName": ["explorer.exe"]})

        result = analyzer.compare_dumps(base, target, pd.DataFrame(), pd.DataFrame())
        assert "svchost.exe" in result["missing_processes"]

    def test_new_connection_detection(self, analyzer):
        """Detects new network connections."""
        base_net = pd.DataFrame({"ForeignAddr": ["8.8.8.8"], "Owner": ["chrome.exe"]})
        target_net = pd.DataFrame({"ForeignAddr": ["8.8.8.8", "198.51.100.1"], "Owner": ["chrome.exe", "malware.exe"]})

        result = analyzer.compare_dumps(
            pd.DataFrame(), pd.DataFrame(), base_net, target_net
        )
        new_ips = [c["ip"] for c in result["new_connections"]]
        assert "198.51.100.1" in new_ips
