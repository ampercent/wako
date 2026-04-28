"""
Tests for the Memory Artifact Correlation Engine.
Run with: python -m pytest tests/test_correlation.py -v
"""

import time

import pandas as pd
import pytest

from pipeline.correlation import (
    build_process_graph,
    correlate_artifacts,
    explain_process,
    export_graph_json,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def pslist_df() -> pd.DataFrame:
    """Process list with a mix of normal and suspicious processes."""
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
    """Network connections tied to specific PIDs."""
    return pd.DataFrame({
        "PID":         [2780, 2780, 3010, 1234],
        "Proto":       ["TCPv4", "TCPv4", "TCPv4", "TCPv4"],
        "LocalAddr":   ["192.168.1.10"] * 4,
        "ForeignAddr": ["198.51.100.1", "0.0.0.0", "203.0.113.50", "10.0.0.5"],
        "State":       ["ESTABLISHED", "LISTENING", "ESTABLISHED", "ESTABLISHED"],
        "Owner":       ["BitTorrent.exe", "BitTorrent.exe", "AnyDesk.exe", "powershell.exe"],
    })


@pytest.fixture
def malfind_df() -> pd.DataFrame:
    """Malfind hits for specific PIDs."""
    return pd.DataFrame({
        "PID":        [1234, 5678],
        "Process":    ["powershell.exe", "cmd.exe"],
        "Protection": ["PAGE_EXECUTE_READWRITE", "PAGE_EXECUTE_READWRITE"],
    })


# ---------------------------------------------------------------------------
# Core correlation tests
# ---------------------------------------------------------------------------

class TestCorrelateArtifacts:
    """Tests for the correlate_artifacts function."""

    def test_basic_correlation(self, pslist_df, netscan_df, malfind_df):
        """Merge produces correct flags and non-empty result."""
        result = correlate_artifacts(pslist_df, netscan_df, malfind_df)

        assert not result.empty
        assert len(result) == len(pslist_df)

        # Required columns present
        for col in ("has_network", "has_injection", "suspicious_parent", "correlation_score"):
            assert col in result.columns, f"Missing column: {col}"

    def test_network_flag(self, pslist_df, netscan_df, malfind_df):
        """PIDs present in netscan get has_network=True."""
        result = correlate_artifacts(pslist_df, netscan_df, malfind_df)

        net_row = result[result["PID"] == 2780].iloc[0]
        assert net_row["has_network"] is True or net_row["has_network"] == True

        no_net_row = result[result["PID"] == 4444].iloc[0]
        assert no_net_row["has_network"] is False or no_net_row["has_network"] == False

    def test_injection_flag(self, pslist_df, netscan_df, malfind_df):
        """PIDs present in malfind get has_injection=True."""
        result = correlate_artifacts(pslist_df, netscan_df, malfind_df)

        inj_row = result[result["PID"] == 1234].iloc[0]
        assert inj_row["has_injection"] == True

        clean_row = result[result["PID"] == 1000].iloc[0]
        assert clean_row["has_injection"] == False

    def test_suspicious_parent(self, pslist_df, netscan_df, malfind_df):
        """cmd.exe spawned by winword.exe should be flagged."""
        result = correlate_artifacts(pslist_df, netscan_df, malfind_df)

        # PID 5678 is cmd.exe with PPID 4444 (winword.exe)
        cmd_row = result[result["PID"] == 5678].iloc[0]
        assert cmd_row["suspicious_parent"] == True

    def test_scoring(self, pslist_df, netscan_df, malfind_df):
        """
        PID 1234 (powershell.exe): has_network(+2) + has_injection(+3)
            + suspicious_parent(+2) + name(+1) = 8.
        """
        result = correlate_artifacts(pslist_df, netscan_df, malfind_df)
        ps_row = result[result["PID"] == 1234].iloc[0]
        assert ps_row["correlation_score"] == 8

    def test_sorted_descending(self, pslist_df, netscan_df, malfind_df):
        """Results are sorted by correlation_score descending."""
        result = correlate_artifacts(pslist_df, netscan_df, malfind_df)
        scores = result["correlation_score"].tolist()
        assert scores == sorted(scores, reverse=True)

    def test_output_columns(self, pslist_df, netscan_df, malfind_df):
        """Output has the seven required columns."""
        result = correlate_artifacts(pslist_df, netscan_df, malfind_df)
        required = {"PID", "ImageFileName", "PPID", "has_network",
                     "has_injection", "suspicious_parent", "correlation_score"}
        assert required.issubset(set(result.columns))


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------

class TestEdgeCases:
    """Edge cases and defensive handling."""

    def test_empty_pslist(self):
        """Empty pslist returns empty result with correct columns."""
        result = correlate_artifacts(
            pd.DataFrame(), pd.DataFrame(), pd.DataFrame()
        )
        assert result.empty
        assert "correlation_score" in result.columns

    def test_none_pslist(self):
        """None pslist returns empty result."""
        result = correlate_artifacts(None, pd.DataFrame(), pd.DataFrame())
        assert result.empty

    def test_empty_netscan_and_malfind(self, pslist_df):
        """No network or injection data → all flags False, score 0 for normal procs."""
        result = correlate_artifacts(pslist_df, pd.DataFrame(), pd.DataFrame())
        explorer = result[result["PID"] == 1000].iloc[0]
        assert explorer["has_network"] == False
        assert explorer["has_injection"] == False
        assert explorer["correlation_score"] == 0

    def test_none_netscan_and_malfind(self, pslist_df):
        """None network/malfind inputs are handled gracefully."""
        result = correlate_artifacts(pslist_df, None, None)
        assert not result.empty
        assert all(result["has_network"] == False)
        assert all(result["has_injection"] == False)

    def test_preserves_extra_columns(self, pslist_df, netscan_df, malfind_df):
        """Extra columns in pslist_df (like CreateTime) are preserved."""
        result = correlate_artifacts(pslist_df, netscan_df, malfind_df)
        assert "CreateTime" in result.columns


# ---------------------------------------------------------------------------
# explain_process tests
# ---------------------------------------------------------------------------

class TestExplainProcess:
    """Tests for explain_process."""

    def test_explain_suspicious(self, pslist_df, netscan_df, malfind_df):
        """Explanation for powershell.exe (PID 1234) mentions key indicators."""
        result = correlate_artifacts(pslist_df, netscan_df, malfind_df)
        explanation = explain_process(1234, result, netscan_df)

        assert "powershell.exe" in explanation
        assert "1234" in explanation
        assert "network" in explanation.lower()
        assert "injection" in explanation.lower()

    def test_explain_clean(self, pslist_df, netscan_df, malfind_df):
        """Clean process gets 'no suspicious indicators' message."""
        result = correlate_artifacts(pslist_df, pd.DataFrame(), pd.DataFrame())
        explanation = explain_process(1000, result)
        assert "no suspicious" in explanation.lower()

    def test_explain_missing_pid(self, pslist_df, netscan_df, malfind_df):
        """Missing PID returns 'no data' message."""
        result = correlate_artifacts(pslist_df, netscan_df, malfind_df)
        explanation = explain_process(99999, result)
        assert "No data" in explanation


# ---------------------------------------------------------------------------
# Graph tests
# ---------------------------------------------------------------------------

class TestBuildProcessGraph:
    """Tests for build_process_graph and export."""

    def test_graph_nodes(self, pslist_df, netscan_df, malfind_df):
        """Graph has at least one node per process."""
        result = correlate_artifacts(pslist_df, netscan_df, malfind_df)
        G, _ = build_process_graph(result, netscan_df)

        # At least process nodes
        process_nodes = [n for n, d in G.nodes(data=True) if d.get("node_type") == "process"]
        assert len(process_nodes) == len(pslist_df)

    def test_graph_parent_child_edges(self, pslist_df, netscan_df, malfind_df):
        """Parent-child edges exist."""
        result = correlate_artifacts(pslist_df, netscan_df, malfind_df)
        G, _ = build_process_graph(result, netscan_df)

        pc_edges = [(u, v) for u, v, d in G.edges(data=True) if d.get("edge_type") == "parent_child"]
        assert len(pc_edges) > 0

    def test_graph_network_edges(self, pslist_df, netscan_df, malfind_df):
        """Network edges connect processes to IP addresses."""
        result = correlate_artifacts(pslist_df, netscan_df, malfind_df)
        G, _ = build_process_graph(result, netscan_df)

        net_edges = [(u, v) for u, v, d in G.edges(data=True) if d.get("edge_type") == "network"]
        assert len(net_edges) > 0

    def test_graph_json_export(self, pslist_df, netscan_df, malfind_df, tmp_path):
        """JSON export writes valid file."""
        result = correlate_artifacts(pslist_df, netscan_df, malfind_df)
        out_file = str(tmp_path / "graph.json")
        json_str = export_graph_json(result, netscan_df, out_file)

        assert len(json_str) > 0
        import json
        data = json.loads(json_str)
        assert "nodes" in data
        # networkx 3.x uses "edges", older versions use "links"
        assert "links" in data or "edges" in data

    def test_empty_graph(self):
        """Empty input produces empty graph."""
        G, data = build_process_graph(pd.DataFrame())
        assert len(G.nodes) == 0


# ---------------------------------------------------------------------------
# Performance
# ---------------------------------------------------------------------------

class TestPerformance:
    """Verify that correlation scales to large datasets."""

    def test_large_dataset(self):
        """100k processes correlate in under 5 seconds."""
        n = 100_000
        pslist = pd.DataFrame({
            "PID": range(n),
            "PPID": [max(0, i - 1) for i in range(n)],
            "ImageFileName": ["svchost.exe"] * n,
        })
        netscan = pd.DataFrame({
            "PID": list(range(0, n, 10)),  # 10% have network
        })
        malfind = pd.DataFrame({
            "PID": list(range(0, n, 100)),  # 1% have injection
        })

        start = time.time()
        result = correlate_artifacts(pslist, netscan, malfind)
        elapsed = time.time() - start

        assert len(result) == n
        assert elapsed < 5.0, f"Took {elapsed:.2f}s — too slow for 100k rows"
