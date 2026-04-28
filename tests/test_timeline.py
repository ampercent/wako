"""
Tests for the Timeline Reconstruction Engine.
Run with: python -m pytest tests/test_timeline.py -v
"""

import time

import pandas as pd
import pytest

from pipeline.correlation import correlate_artifacts
from pipeline.risk_scoring import enrich_with_explanations
from pipeline.timeline import (
    build_timeline,
    generate_event_description,
    summarize_timeline,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def pslist_df() -> pd.DataFrame:
    return pd.DataFrame({
        "PID":           [1000, 1234, 2780, 3010, 4444, 5678],
        "PPID":          [500,  4444, 1384, 1384, 1384, 4444],
        "ImageFileName": [
            "explorer.exe", "powershell.exe", "BitTorrent.exe",
            "AnyDesk.exe", "winword.exe", "cmd.exe",
        ],
        "CreateTime": pd.to_datetime([
            "2026-01-15 06:01:44", "2026-01-15 12:40:44",
            "2026-01-15 08:06:27", "2026-01-15 10:15:30",
            "2026-01-15 09:00:00", "2026-01-15 12:41:00",
        ]),
    })


@pytest.fixture
def netscan_df() -> pd.DataFrame:
    return pd.DataFrame({
        "PID":         [2780, 3010, 1234],
        "Proto":       ["TCPv4"] * 3,
        "LocalAddr":   ["192.168.1.10"] * 3,
        "ForeignAddr": ["198.51.100.1", "203.0.113.50", "10.0.0.5"],
        "ForeignPort": [8080, 443, 4444],
        "State":       ["ESTABLISHED", "ESTABLISHED", "ESTABLISHED"],
        "Owner":       ["BitTorrent.exe", "AnyDesk.exe", "powershell.exe"],
        "Created": pd.to_datetime([
            "2026-01-15 08:10:00", "2026-01-15 10:16:00",
            "2026-01-15 12:41:30",
        ]),
    })


@pytest.fixture
def malfind_df() -> pd.DataFrame:
    return pd.DataFrame({
        "PID":        [1234, 5678],
        "Process":    ["powershell.exe", "cmd.exe"],
        "Protection": ["PAGE_EXECUTE_READWRITE"] * 2,
    })


@pytest.fixture
def enriched_df(pslist_df, netscan_df, malfind_df) -> pd.DataFrame:
    correlated = correlate_artifacts(pslist_df, netscan_df, malfind_df)
    return enrich_with_explanations(correlated)


# ---------------------------------------------------------------------------
# build_timeline tests
# ---------------------------------------------------------------------------

class TestBuildTimeline:
    """Tests for the build_timeline function."""

    def test_basic_timeline(self, pslist_df, netscan_df, malfind_df, enriched_df):
        """Timeline combines events from all sources."""
        tl = build_timeline(pslist_df, netscan_df, malfind_df, enriched_df)
        assert not tl.empty
        assert len(tl) == len(pslist_df) + len(netscan_df) + len(malfind_df)

    def test_required_columns(self, pslist_df, netscan_df, malfind_df, enriched_df):
        """All expected columns present."""
        tl = build_timeline(pslist_df, netscan_df, malfind_df, enriched_df)
        expected = {"timestamp", "event_type", "pid", "process_name",
                    "severity", "is_suspicious", "description"}
        assert expected.issubset(set(tl.columns))

    def test_event_types(self, pslist_df, netscan_df, malfind_df, enriched_df):
        """All three event types present."""
        tl = build_timeline(pslist_df, netscan_df, malfind_df, enriched_df)
        types = set(tl["event_type"].unique())
        assert types == {"process_start", "network_connect", "injection"}

    def test_sorted_by_timestamp(self, pslist_df, netscan_df, malfind_df, enriched_df):
        """Events are sorted chronologically."""
        tl = build_timeline(pslist_df, netscan_df, malfind_df, enriched_df)
        valid = tl["timestamp"].dropna()
        assert valid.is_monotonic_increasing

    def test_nat_at_end(self, pslist_df, netscan_df, malfind_df, enriched_df):
        """Events without timestamps are at the end."""
        tl = build_timeline(pslist_df, netscan_df, malfind_df, enriched_df)
        # Find first NaT index and ensure all after it are also NaT
        has_ts = tl["timestamp"].notna()
        if not has_ts.all():
            first_nat_idx = has_ts[~has_ts].index[0]
            assert tl.loc[first_nat_idx:, "timestamp"].isna().all()

    def test_suspicion_flag(self, pslist_df, netscan_df, malfind_df, enriched_df):
        """is_suspicious is True for HIGH/MEDIUM severity."""
        tl = build_timeline(pslist_df, netscan_df, malfind_df, enriched_df)
        for _, row in tl.iterrows():
            if row["severity"] in ("HIGH", "MEDIUM"):
                assert row["is_suspicious"] == True
            else:
                assert row["is_suspicious"] == False

    def test_descriptions_non_empty(self, pslist_df, netscan_df, malfind_df, enriched_df):
        """All events have non-empty descriptions."""
        tl = build_timeline(pslist_df, netscan_df, malfind_df, enriched_df)
        assert all(len(str(d)) > 5 for d in tl["description"])

    def test_process_start_description(self, pslist_df, netscan_df, malfind_df, enriched_df):
        """Process start events mention 'started'."""
        tl = build_timeline(pslist_df, netscan_df, malfind_df, enriched_df)
        starts = tl[tl["event_type"] == "process_start"]
        assert all("started" in str(d) for d in starts["description"])

    def test_network_description(self, pslist_df, netscan_df, malfind_df, enriched_df):
        """Network events mention 'connected to'."""
        tl = build_timeline(pslist_df, netscan_df, malfind_df, enriched_df)
        nets = tl[tl["event_type"] == "network_connect"]
        assert all("connected to" in str(d) for d in nets["description"])

    def test_injection_description(self, pslist_df, netscan_df, malfind_df, enriched_df):
        """Injection events mention 'injection'."""
        tl = build_timeline(pslist_df, netscan_df, malfind_df, enriched_df)
        inj = tl[tl["event_type"] == "injection"]
        assert all("injection" in str(d).lower() for d in inj["description"])


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------

class TestEdgeCases:
    """Edge cases and defensive handling."""

    def test_all_empty(self):
        """All empty inputs produce empty timeline."""
        tl = build_timeline()
        assert tl.empty
        assert "timestamp" in tl.columns

    def test_all_none(self):
        """All None inputs produce empty timeline."""
        tl = build_timeline(None, None, None, None)
        assert tl.empty

    def test_pslist_only(self, pslist_df):
        """Timeline works with pslist only."""
        tl = build_timeline(pslist_df=pslist_df)
        assert len(tl) == len(pslist_df)
        assert all(tl["event_type"] == "process_start")

    def test_netscan_only(self, netscan_df):
        """Timeline works with netscan only."""
        tl = build_timeline(netscan_df=netscan_df)
        assert len(tl) == len(netscan_df)
        assert all(tl["event_type"] == "network_connect")

    def test_malfind_only(self, malfind_df):
        """Timeline works with malfind only."""
        tl = build_timeline(malfind_df=malfind_df)
        assert len(tl) == len(malfind_df)
        assert all(tl["event_type"] == "injection")

    def test_missing_timestamp_column(self):
        """DataFrame without any known timestamp column handles gracefully."""
        df = pd.DataFrame({"PID": [1, 2], "ImageFileName": ["a.exe", "b.exe"]})
        tl = build_timeline(pslist_df=df)
        assert len(tl) == 2
        assert tl["timestamp"].isna().all()

    def test_no_correlation_df(self, pslist_df, netscan_df, malfind_df):
        """Without correlation_df, severity defaults to LOW."""
        tl = build_timeline(pslist_df, netscan_df, malfind_df)
        starts = tl[tl["event_type"] == "process_start"]
        assert all(starts["severity"] == "LOW")


# ---------------------------------------------------------------------------
# generate_event_description tests
# ---------------------------------------------------------------------------

class TestGenerateEventDescription:
    """Tests for the standalone description generator."""

    def test_process_start(self):
        row = pd.Series({
            "event_type": "process_start",
            "pid": 42,
            "process_name": "notepad.exe",
        })
        desc = generate_event_description(row)
        assert "notepad.exe" in desc
        assert "started" in desc

    def test_network_connect(self):
        row = pd.Series({
            "event_type": "network_connect",
            "pid": 100,
            "process_name": "chrome.exe",
            "ForeignAddr": "1.2.3.4",
            "ForeignPort": 443,
            "State": "ESTABLISHED",
        })
        desc = generate_event_description(row)
        assert "connected to" in desc
        assert "1.2.3.4" in desc

    def test_injection(self):
        row = pd.Series({
            "event_type": "injection",
            "pid": 200,
            "process_name": "cmd.exe",
            "Protection": "PAGE_EXECUTE_READWRITE",
        })
        desc = generate_event_description(row)
        assert "injection" in desc.lower()
        assert "cmd.exe" in desc

    def test_unknown_event(self):
        row = pd.Series({
            "event_type": "custom_event",
            "pid": 300,
            "process_name": "x.exe",
        })
        desc = generate_event_description(row)
        assert "custom_event" in desc


# ---------------------------------------------------------------------------
# summarize_timeline tests
# ---------------------------------------------------------------------------

class TestSummarizeTimeline:
    """Tests for the summarize_timeline function."""

    def test_basic_summary(self, pslist_df, netscan_df, malfind_df, enriched_df):
        tl = build_timeline(pslist_df, netscan_df, malfind_df, enriched_df)
        summary = summarize_timeline(tl)
        assert "event" in summary.lower()
        assert str(len(tl)) in summary

    def test_mentions_event_types(self, pslist_df, netscan_df, malfind_df, enriched_df):
        tl = build_timeline(pslist_df, netscan_df, malfind_df, enriched_df)
        summary = summarize_timeline(tl)
        assert "process start" in summary.lower()
        assert "network" in summary.lower()
        assert "injection" in summary.lower()

    def test_mentions_suspicious(self, pslist_df, netscan_df, malfind_df, enriched_df):
        tl = build_timeline(pslist_df, netscan_df, malfind_df, enriched_df)
        summary = summarize_timeline(tl)
        assert "suspicious" in summary.lower()

    def test_empty_timeline(self):
        summary = summarize_timeline(pd.DataFrame())
        assert "no events" in summary.lower()

    def test_none_timeline(self):
        summary = summarize_timeline(None)
        assert "no events" in summary.lower()

    def test_time_span(self, pslist_df, netscan_df, malfind_df, enriched_df):
        """Summary mentions time span."""
        tl = build_timeline(pslist_df, netscan_df, malfind_df, enriched_df)
        summary = summarize_timeline(tl)
        assert "span" in summary.lower()


# ---------------------------------------------------------------------------
# Performance
# ---------------------------------------------------------------------------

class TestPerformance:
    """Verify timeline scales to large datasets."""

    def test_large_timeline(self):
        """100k events build in under 5 seconds."""
        n = 100_000
        pslist = pd.DataFrame({
            "PID": range(n),
            "PPID": [max(0, i - 1) for i in range(n)],
            "ImageFileName": ["svchost.exe"] * n,
            "CreateTime": pd.date_range("2026-01-01", periods=n, freq="s"),
        })

        start = time.time()
        tl = build_timeline(pslist_df=pslist)
        elapsed = time.time() - start

        assert len(tl) == n
        assert elapsed < 5.0, f"Took {elapsed:.2f}s — too slow for 100k events"
