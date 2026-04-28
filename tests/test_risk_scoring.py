"""
Tests for the Risk Scoring and Explanation Layer.
Run with: python -m pytest tests/test_risk_scoring.py -v
"""

import time

import pandas as pd
import pytest

from pipeline.correlation import correlate_artifacts
from pipeline.risk_scoring import (
    classify_severity,
    enrich_with_explanations,
    explain_process_row,
    explain_summary,
    generate_alerts,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def correlated_df() -> pd.DataFrame:
    """Pre-correlated DataFrame with known flag values."""
    pslist = pd.DataFrame({
        "PID":           [1000, 1234, 2780, 3010, 4444, 5678],
        "PPID":          [500,  4444, 1384, 1384, 1384, 4444],
        "ImageFileName": [
            "explorer.exe", "powershell.exe", "BitTorrent.exe",
            "AnyDesk.exe", "winword.exe", "cmd.exe",
        ],
    })
    netscan = pd.DataFrame({
        "PID":         [2780, 2780, 3010, 1234],
        "Proto":       ["TCPv4"] * 4,
        "LocalAddr":   ["192.168.1.10"] * 4,
        "ForeignAddr": ["198.51.100.1", "0.0.0.0", "203.0.113.50", "10.0.0.5"],
        "State":       ["ESTABLISHED", "LISTENING", "ESTABLISHED", "ESTABLISHED"],
    })
    malfind = pd.DataFrame({
        "PID":        [1234, 5678],
        "Process":    ["powershell.exe", "cmd.exe"],
        "Protection": ["PAGE_EXECUTE_READWRITE"] * 2,
    })
    return correlate_artifacts(pslist, netscan, malfind)


# ---------------------------------------------------------------------------
# classify_severity tests
# ---------------------------------------------------------------------------

class TestClassifySeverity:
    """Tests for the classify_severity function."""

    def test_high_severity(self):
        assert classify_severity(6) == "HIGH"
        assert classify_severity(8) == "HIGH"
        assert classify_severity(100) == "HIGH"

    def test_medium_severity(self):
        assert classify_severity(3) == "MEDIUM"
        assert classify_severity(4) == "MEDIUM"
        assert classify_severity(5) == "MEDIUM"

    def test_low_severity(self):
        assert classify_severity(0) == "LOW"
        assert classify_severity(1) == "LOW"
        assert classify_severity(2) == "LOW"

    def test_negative_score(self):
        """Negative scores should be LOW."""
        assert classify_severity(-1) == "LOW"


# ---------------------------------------------------------------------------
# explain_process_row tests
# ---------------------------------------------------------------------------

class TestExplainProcessRow:
    """Tests for the explain_process_row function."""

    def test_full_explanation(self, correlated_df):
        """powershell.exe (PID 1234) should mention all indicators."""
        row = correlated_df[correlated_df["PID"] == 1234].iloc[0]
        explanation = explain_process_row(row)

        assert "powershell.exe" in explanation
        assert "1234" in explanation
        assert "network" in explanation.lower()
        assert "injection" in explanation.lower()

    def test_clean_process(self, correlated_df):
        """explorer.exe (PID 1000) has no indicators."""
        row = correlated_df[correlated_df["PID"] == 1000].iloc[0]
        explanation = explain_process_row(row)

        assert "no suspicious" in explanation.lower()

    def test_missing_fields(self):
        """Should handle missing/null fields without crashing."""
        sparse_row = pd.Series({"PID": 999})
        explanation = explain_process_row(sparse_row)
        assert "999" in explanation
        assert isinstance(explanation, str)

    def test_null_values(self):
        """Should handle NaN values in fields."""
        row = pd.Series({
            "PID": 42,
            "ImageFileName": None,
            "has_network": None,
            "has_injection": None,
            "suspicious_parent": None,
            "parent_name": None,
        })
        explanation = explain_process_row(row)
        assert isinstance(explanation, str)
        assert "42" in explanation


# ---------------------------------------------------------------------------
# enrich_with_explanations tests
# ---------------------------------------------------------------------------

class TestEnrichWithExplanations:
    """Tests for the enrich_with_explanations function."""

    def test_adds_columns(self, correlated_df):
        """Enrichment adds severity and explanation columns."""
        result = enrich_with_explanations(correlated_df)
        assert "severity" in result.columns
        assert "explanation" in result.columns

    def test_preserves_original_columns(self, correlated_df):
        """Original columns are preserved."""
        result = enrich_with_explanations(correlated_df)
        for col in ("PID", "ImageFileName", "correlation_score",
                     "has_network", "has_injection", "suspicious_parent"):
            assert col in result.columns

    def test_sorted_by_severity_then_score(self, correlated_df):
        """HIGH rows come before MEDIUM, MEDIUM before LOW, and within
        each group scores are descending."""
        result = enrich_with_explanations(correlated_df)
        severity_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
        order_vals = result["severity"].map(severity_order).tolist()
        assert order_vals == sorted(order_vals)

    def test_correct_severity_assignment(self, correlated_df):
        """PID 1234 (score=8) should be HIGH."""
        result = enrich_with_explanations(correlated_df)
        row = result[result["PID"] == 1234].iloc[0]
        assert row["severity"] == "HIGH"

    def test_empty_input(self):
        """Empty DataFrame returns empty with correct columns."""
        result = enrich_with_explanations(pd.DataFrame())
        assert result.empty
        assert "severity" in result.columns
        assert "explanation" in result.columns

    def test_none_input(self):
        """None returns empty DataFrame."""
        result = enrich_with_explanations(None)
        assert result.empty


# ---------------------------------------------------------------------------
# generate_alerts tests
# ---------------------------------------------------------------------------

class TestGenerateAlerts:
    """Tests for the generate_alerts function."""

    def test_filters_low(self, correlated_df):
        """LOW severity processes are excluded."""
        enriched = enrich_with_explanations(correlated_df)
        alerts = generate_alerts(enriched)
        assert "LOW" not in alerts["severity"].values

    def test_contains_high_and_medium(self, correlated_df):
        """Alerts contain HIGH and/or MEDIUM entries."""
        enriched = enrich_with_explanations(correlated_df)
        alerts = generate_alerts(enriched)
        assert len(alerts) > 0
        assert set(alerts["severity"].unique()).issubset({"HIGH", "MEDIUM"})

    def test_output_columns(self, correlated_df):
        """Alert output has exactly the expected columns."""
        enriched = enrich_with_explanations(correlated_df)
        alerts = generate_alerts(enriched)
        expected = {"PID", "ImageFileName", "severity",
                    "correlation_score", "explanation"}
        assert set(alerts.columns) == expected

    def test_empty_input(self):
        """Empty DataFrame returns empty alerts."""
        alerts = generate_alerts(pd.DataFrame())
        assert alerts.empty

    def test_all_low_scores(self):
        """When all scores are LOW, alerts should be empty."""
        df = pd.DataFrame({
            "PID": [1, 2, 3],
            "ImageFileName": ["a.exe", "b.exe", "c.exe"],
            "correlation_score": [0, 0, 1],
            "has_network": [False] * 3,
            "has_injection": [False] * 3,
            "suspicious_parent": [False] * 3,
        })
        enriched = enrich_with_explanations(df)
        alerts = generate_alerts(enriched)
        assert len(alerts) == 0


# ---------------------------------------------------------------------------
# explain_summary tests
# ---------------------------------------------------------------------------

class TestExplainSummary:
    """Tests for the explain_summary function."""

    def test_mentions_high_risk(self, correlated_df):
        """Summary mentions high-risk count."""
        enriched = enrich_with_explanations(correlated_df)
        summary = explain_summary(enriched)
        assert "high-risk" in summary.lower()

    def test_mentions_injection(self, correlated_df):
        """Summary mentions injection if present."""
        enriched = enrich_with_explanations(correlated_df)
        summary = explain_summary(enriched)
        assert "injection" in summary.lower()

    def test_mentions_suspicious_parent(self, correlated_df):
        """Summary mentions suspicious parent if present."""
        enriched = enrich_with_explanations(correlated_df)
        summary = explain_summary(enriched)
        assert "suspicious parent" in summary.lower()

    def test_empty_input(self):
        """Empty DataFrame gives 'no processes' message."""
        summary = explain_summary(pd.DataFrame())
        assert "no processes" in summary.lower()

    def test_none_input(self):
        summary = explain_summary(None)
        assert "no processes" in summary.lower()


# ---------------------------------------------------------------------------
# Performance
# ---------------------------------------------------------------------------

class TestPerformance:
    """Verify enrichment scales to large datasets."""

    def test_large_dataset_enrichment(self):
        """100k rows enrich in under 10 seconds."""
        n = 100_000
        df = pd.DataFrame({
            "PID": range(n),
            "PPID": [max(0, i - 1) for i in range(n)],
            "ImageFileName": ["svchost.exe"] * n,
            "parent_name": ["services.exe"] * n,
            "has_network": [i % 10 == 0 for i in range(n)],
            "has_injection": [i % 100 == 0 for i in range(n)],
            "suspicious_parent": [False] * n,
            "correlation_score": [2 if i % 10 == 0 else 0 for i in range(n)],
        })

        start = time.time()
        enriched = enrich_with_explanations(df)
        elapsed = time.time() - start

        assert len(enriched) == n
        assert "severity" in enriched.columns
        assert elapsed < 10.0, f"Took {elapsed:.2f}s — too slow for 100k rows"
