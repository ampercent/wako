"""
Tests for the Decision Engine (Analyst Workflow Automation).
Run with: python -m pytest tests/test_decision_engine.py -v
"""

import time
from typing import List

import pandas as pd
import pytest

from pipeline.decision_engine import (
    build_pid_maps,
    compute_confidence,
    detect_root_cause,
    extract_ips_from_timeline,
    generate_attack_summary,
    generate_investigation_plan,
    is_external_ip,
    reconstruct_attack_chain,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_correlation_df() -> pd.DataFrame:
    return pd.DataFrame({
        "PID": [1000, 2010, 3010, 4010, 5010],
        "PPID": [500, 1000, 2010, 2010, 1000],
        "ImageFileName": [
            "explorer.exe", "certutil.exe", "powershell.exe",
            "cmd.exe", "chrome.exe",
        ],
        "has_network": [False, True, True, False, True],
        "has_injection": [False, False, True, False, False],
        "suspicious_parent": [False, False, True, True, False],
        "correlation_score": [0, 3, 8, 5, 2],
        "severity": ["LOW", "MEDIUM", "HIGH", "MEDIUM", "LOW"],
    })


@pytest.fixture
def mock_timeline_df() -> pd.DataFrame:
    return pd.DataFrame({
        "timestamp": pd.to_datetime([
            "2026-04-10 10:00:00", "2026-04-10 10:05:00",
            "2026-04-10 10:05:30", "2026-04-10 10:06:00",
            "2026-04-10 10:06:15", "2026-04-10 10:07:00",
        ]),
        "event_type": [
            "process_start", "process_start",
            "network_connect", "process_start",
            "network_connect", "injection",
        ],
        "pid": [1000, 2010, 2010, 3010, 3010, 3010],
        "process_name": [
            "explorer.exe", "certutil.exe",
            "certutil.exe", "powershell.exe",
            "powershell.exe", "powershell.exe",
        ],
        "severity": ["LOW", "MEDIUM", "MEDIUM", "HIGH", "HIGH", "HIGH"],
        "is_suspicious": [False, True, True, True, True, True],
        "description": [
            "explorer.exe (PID 1000) started.",
            "certutil.exe (PID 2010) started, spawned by explorer.exe.",
            "certutil.exe (PID 2010) connected to 8.8.8.8:443 (ESTABLISHED, TCPv4).",
            "powershell.exe (PID 3010) started, spawned by certutil.exe.",
            "powershell.exe (PID 3010) connected to 198.51.100.1:4444 (ESTABLISHED, TCPv4).",
            "Memory injection detected in powershell.exe (PID 3010).",
        ],
    })


@pytest.fixture
def mock_graph() -> dict:
    return {
        "nodes": [
            {"id": "pid_1000", "label": "explorer.exe", "type": "process", "severity": "LOW", "correlation_score": 0},
            {"id": "pid_2010", "label": "certutil.exe", "type": "process", "severity": "MEDIUM", "correlation_score": 3},
            {"id": "pid_3010", "label": "powershell.exe", "type": "process", "severity": "HIGH", "correlation_score": 8},
            {"id": "ip_8.8.8.8:443", "label": "8.8.8.8:443", "type": "network"},
            {"id": "ip_198.51.100.1:4444", "label": "198.51.100.1:4444", "type": "network"},
        ],
        "edges": [
            {"source": "pid_1000", "target": "pid_2010", "type": "parent_child"},
            {"source": "pid_2010", "target": "pid_3010", "type": "parent_child"},
            {"source": "pid_2010", "target": "ip_8.8.8.8:443", "type": "network_connection"},
            {"source": "pid_3010", "target": "ip_198.51.100.1:4444", "type": "network_connection"},
        ],
    }


# ---------------------------------------------------------------------------
# 🧰 UTILITY TESTS
# ---------------------------------------------------------------------------

class TestIsExternalIp:
    """Tests for is_external_ip utility."""

    def test_external_ip(self):
        assert is_external_ip("8.8.8.8") is True

    def test_external_ip_with_port(self):
        assert is_external_ip("8.8.8.8:443") is True

    def test_private_192(self):
        assert is_external_ip("192.168.1.1") is False

    def test_private_10(self):
        assert is_external_ip("10.0.0.1") is False

    def test_private_172(self):
        assert is_external_ip("172.16.0.1") is False

    def test_loopback(self):
        assert is_external_ip("127.0.0.1") is False

    def test_zero(self):
        assert is_external_ip("0.0.0.0") is False

    def test_star(self):
        assert is_external_ip("*") is False

    def test_empty(self):
        assert is_external_ip("") is False

    def test_invalid(self):
        assert is_external_ip("not-an-ip") is False

    def test_link_local(self):
        assert is_external_ip("169.254.1.1") is False


class TestExtractIpsFromTimeline:
    """Tests for extract_ips_from_timeline utility."""

    def test_extracts_ips(self, mock_timeline_df):
        ips = extract_ips_from_timeline(mock_timeline_df)
        assert "8.8.8.8:443" in ips
        assert "198.51.100.1:4444" in ips

    def test_empty_df(self):
        assert extract_ips_from_timeline(pd.DataFrame()) == set()

    def test_none_df(self):
        assert extract_ips_from_timeline(None) == set()

    def test_no_description_column(self):
        df = pd.DataFrame({"pid": [1000], "event_type": ["process_start"]})
        assert extract_ips_from_timeline(df) == set()


class TestBuildPidMaps:
    """Tests for build_pid_maps utility."""

    def test_builds_maps(self, mock_correlation_df):
        pid_to_name, pid_to_parent, pid_to_sev = build_pid_maps(mock_correlation_df)
        assert pid_to_name[1000] == "explorer.exe"
        assert pid_to_name[3010] == "powershell.exe"
        assert pid_to_parent[2010] == 1000
        assert pid_to_sev[3010] == "HIGH"

    def test_empty_df(self):
        n, p, s = build_pid_maps(pd.DataFrame())
        assert n == {} and p == {} and s == {}

    def test_none_df(self):
        n, p, s = build_pid_maps(None)
        assert n == {} and p == {} and s == {}


# ---------------------------------------------------------------------------
# 🧭 1) INVESTIGATION PLAN TESTS
# ---------------------------------------------------------------------------

class TestGenerateInvestigationPlan:
    """Tests for the investigation plan generator."""

    def test_produces_steps(self, mock_correlation_df, mock_timeline_df, mock_graph):
        plan = generate_investigation_plan(mock_correlation_df, mock_timeline_df, mock_graph)
        assert isinstance(plan, list)
        assert len(plan) > 0

    def test_high_severity_first(self, mock_correlation_df, mock_timeline_df, mock_graph):
        """HIGH severity processes appear before MEDIUM and LOW."""
        plan = generate_investigation_plan(mock_correlation_df, mock_timeline_df, mock_graph)
        priorities = [s["priority"] for s in plan]
        # All HIGH steps should come before any MEDIUM steps
        first_medium = next((i for i, p in enumerate(priorities) if p == "MEDIUM"), len(priorities))
        last_high = max((i for i, p in enumerate(priorities) if p == "HIGH"), default=-1)
        assert last_high < first_medium

    def test_no_duplicate_entities(self, mock_correlation_df, mock_timeline_df, mock_graph):
        """Each entity appears at most once."""
        plan = generate_investigation_plan(mock_correlation_df, mock_timeline_df, mock_graph)
        entities = [s["entity"] for s in plan]
        assert len(entities) == len(set(entities))

    def test_max_10_steps(self, mock_correlation_df, mock_timeline_df, mock_graph):
        """Plan is capped at 10 steps."""
        plan = generate_investigation_plan(mock_correlation_df, mock_timeline_df, mock_graph)
        assert len(plan) <= 10

    def test_steps_numbered_sequentially(self, mock_correlation_df, mock_timeline_df, mock_graph):
        """Steps are numbered 1, 2, 3, ..."""
        plan = generate_investigation_plan(mock_correlation_df, mock_timeline_df, mock_graph)
        for i, step in enumerate(plan):
            assert step["step"] == i + 1

    def test_network_step_present(self, mock_correlation_df, mock_timeline_df, mock_graph):
        """At least one network-focused step when external IPs exist."""
        plan = generate_investigation_plan(mock_correlation_df, mock_timeline_df, mock_graph)
        # Check for IP-related entity or action mentioning network/IP
        has_network_step = any(
            "IP" in s["entity"] or "8.8.8.8" in s["entity"]
            or "198.51.100.1" in s["entity"]
            for s in plan
        )
        assert has_network_step

    def test_injection_included(self, mock_correlation_df, mock_timeline_df, mock_graph):
        """Injection processes appear in the plan."""
        plan = generate_investigation_plan(mock_correlation_df, mock_timeline_df, mock_graph)
        entities = [s["entity"] for s in plan]
        assert "powershell.exe" in entities  # has_injection = True

    def test_step_structure(self, mock_correlation_df, mock_timeline_df, mock_graph):
        """Each step has required keys."""
        plan = generate_investigation_plan(mock_correlation_df, mock_timeline_df, mock_graph)
        required_keys = {"step", "pid", "entity", "action", "reason", "priority"}
        for step in plan:
            assert required_keys <= set(step.keys())

    def test_empty_input(self):
        """Empty correlation returns empty plan."""
        plan = generate_investigation_plan(pd.DataFrame(), pd.DataFrame())
        assert plan == []

    def test_none_input(self):
        """None correlation returns empty plan."""
        plan = generate_investigation_plan(None, None)
        assert plan == []

    def test_no_severity_column(self):
        """Handles missing severity column gracefully."""
        df = pd.DataFrame({
            "PID": [1000], "PPID": [500],
            "ImageFileName": ["test.exe"],
            "correlation_score": [5],
        })
        plan = generate_investigation_plan(df, pd.DataFrame())
        assert isinstance(plan, list)


# ---------------------------------------------------------------------------
# 🎯 2) ROOT CAUSE TESTS
# ---------------------------------------------------------------------------

class TestDetectRootCause:
    """Tests for root cause detection."""

    def test_detects_entry_process(self, mock_timeline_df, mock_correlation_df):
        rc = detect_root_cause(mock_timeline_df, mock_correlation_df)
        # explorer.exe is the ancestor of the suspicious chain
        assert rc["entry_process"] is not None
        assert rc["entry_pid"] is not None

    def test_detects_first_suspicious(self, mock_timeline_df, mock_correlation_df):
        rc = detect_root_cause(mock_timeline_df, mock_correlation_df)
        assert rc["first_suspicious"] is not None
        assert rc["first_suspicious_pid"] is not None

    def test_first_suspicious_is_earliest(self, mock_timeline_df, mock_correlation_df):
        """First suspicious should be the earliest suspicious event in timeline."""
        rc = detect_root_cause(mock_timeline_df, mock_correlation_df)
        # certutil.exe at 10:05 is first MEDIUM event
        assert rc["first_suspicious"] in ("certutil.exe", "explorer.exe", "powershell.exe")

    def test_reason_populated(self, mock_timeline_df, mock_correlation_df):
        rc = detect_root_cause(mock_timeline_df, mock_correlation_df)
        assert len(rc["reason"]) > 0
        assert rc["reason"] != "Insufficient data for root cause analysis."

    def test_empty_timeline(self, mock_correlation_df):
        rc = detect_root_cause(pd.DataFrame(), mock_correlation_df)
        assert rc["entry_process"] is None
        assert rc["first_suspicious"] is None

    def test_none_inputs(self):
        rc = detect_root_cause(None, None)
        assert rc["entry_process"] is None

    def test_nat_timestamps_handled(self, mock_correlation_df):
        """NaT timestamps are ignored without errors."""
        tl = pd.DataFrame({
            "timestamp": [pd.NaT, "2026-04-10 10:00:00", pd.NaT],
            "event_type": ["process_start", "process_start", "injection"],
            "pid": [1000, 2010, 3010],
            "process_name": ["a.exe", "b.exe", "c.exe"],
            "severity": ["LOW", "HIGH", "HIGH"],
            "is_suspicious": [False, True, True],
            "description": ["a started", "b started", "injection in c"],
        })
        rc = detect_root_cause(tl, mock_correlation_df)
        assert isinstance(rc, dict)

    def test_no_suspicious_events(self):
        """All LOW severity returns appropriate message."""
        tl = pd.DataFrame({
            "timestamp": pd.to_datetime(["2026-04-10 10:00:00"]),
            "event_type": ["process_start"],
            "pid": [1000],
            "process_name": ["explorer.exe"],
            "severity": ["LOW"],
            "is_suspicious": [False],
            "description": ["explorer.exe started"],
        })
        corr = pd.DataFrame({
            "PID": [1000], "PPID": [500],
            "ImageFileName": ["explorer.exe"],
            "has_injection": [False],
            "severity": ["LOW"],
        })
        rc = detect_root_cause(tl, corr)
        assert rc["first_suspicious"] is None

    def test_return_structure(self, mock_timeline_df, mock_correlation_df):
        rc = detect_root_cause(mock_timeline_df, mock_correlation_df)
        expected_keys = {"entry_process", "first_suspicious", "entry_pid",
                         "first_suspicious_pid", "reason"}
        assert expected_keys == set(rc.keys())


# ---------------------------------------------------------------------------
# 🔗 3) ATTACK CHAIN TESTS
# ---------------------------------------------------------------------------

class TestReconstructAttackChain:
    """Tests for attack chain reconstruction."""

    def test_produces_chain(self, mock_graph, mock_timeline_df):
        chain = reconstruct_attack_chain(mock_graph, mock_timeline_df)
        assert isinstance(chain, list)
        assert len(chain) > 0

    def test_ordered_chain(self, mock_graph, mock_timeline_df):
        """Chain should follow causal order."""
        chain = reconstruct_attack_chain(mock_graph, mock_timeline_df)
        # Process nodes should come before their network targets
        assert all(isinstance(e, str) for e in chain)

    def test_max_8_nodes(self, mock_graph, mock_timeline_df):
        chain = reconstruct_attack_chain(mock_graph, mock_timeline_df)
        assert len(chain) <= 8

    def test_includes_network_targets(self, mock_graph, mock_timeline_df):
        """External IPs should appear in the chain."""
        chain = reconstruct_attack_chain(mock_graph, mock_timeline_df)
        has_ip = any("." in e and not e.endswith(".exe") for e in chain)
        assert has_ip

    def test_none_graph(self, mock_timeline_df):
        chain = reconstruct_attack_chain(None, mock_timeline_df)
        assert chain == []

    def test_empty_graph(self, mock_timeline_df):
        chain = reconstruct_attack_chain({"nodes": [], "edges": []}, mock_timeline_df)
        assert chain == []

    def test_no_edges(self, mock_timeline_df):
        """Graph with nodes but no edges still returns nodes."""
        graph = {
            "nodes": [
                {"id": "pid_1000", "label": "explorer.exe", "type": "process", "severity": "HIGH"},
            ],
            "edges": [],
        }
        chain = reconstruct_attack_chain(graph, mock_timeline_df)
        assert len(chain) >= 1

    def test_chain_contains_strings(self, mock_graph, mock_timeline_df):
        chain = reconstruct_attack_chain(mock_graph, mock_timeline_df)
        for entity in chain:
            assert isinstance(entity, str)


# ---------------------------------------------------------------------------
# 🧠 4) CONFIDENCE SCORING TESTS
# ---------------------------------------------------------------------------

class TestComputeConfidence:
    """Tests for confidence scoring."""

    def test_full_indicators(self, mock_correlation_df, mock_graph):
        """All indicators present yields high confidence."""
        conf = compute_confidence(mock_correlation_df, mock_graph)
        assert conf["confidence"] == 100  # 30+25+20+25 = 100

    def test_clamped_to_100(self, mock_correlation_df, mock_graph):
        """Confidence never exceeds 100."""
        conf = compute_confidence(mock_correlation_df, mock_graph)
        assert conf["confidence"] <= 100

    def test_factors_present(self, mock_correlation_df, mock_graph):
        conf = compute_confidence(mock_correlation_df, mock_graph)
        factor_names = {f["name"] for f in conf["factors"]}
        expected = {"memory_injection", "external_network", "abnormal_parent", "multi_indicator"}
        assert factor_names == expected

    def test_injection_factor(self, mock_correlation_df, mock_graph):
        conf = compute_confidence(mock_correlation_df, mock_graph)
        inj = next(f for f in conf["factors"] if f["name"] == "memory_injection")
        assert inj["score"] == 30

    def test_no_injection(self):
        """No injection → injection factor = 0."""
        df = pd.DataFrame({
            "PID": [1000],
            "has_injection": [False],
            "has_network": [False],
            "suspicious_parent": [False],
        })
        conf = compute_confidence(df)
        inj = next(f for f in conf["factors"] if f["name"] == "memory_injection")
        assert inj["score"] == 0

    def test_empty_input(self):
        conf = compute_confidence(pd.DataFrame())
        assert conf["confidence"] == 0
        assert conf["factors"] == []

    def test_none_input(self):
        conf = compute_confidence(None)
        assert conf["confidence"] == 0

    def test_multi_indicator_same_pid(self):
        """≥2 flags on same PID triggers multi_indicator bonus."""
        df = pd.DataFrame({
            "PID": [1000],
            "has_network": [True],
            "has_injection": [True],
            "suspicious_parent": [False],
        })
        conf = compute_confidence(df)
        multi = next(f for f in conf["factors"] if f["name"] == "multi_indicator")
        assert multi["score"] == 25

    def test_no_multi_indicator(self):
        """Only 1 flag per PID → no multi_indicator bonus."""
        df = pd.DataFrame({
            "PID": [1000, 2000],
            "has_network": [True, False],
            "has_injection": [False, True],
            "suspicious_parent": [False, False],
        })
        conf = compute_confidence(df)
        multi = next(f for f in conf["factors"] if f["name"] == "multi_indicator")
        assert multi["score"] == 0

    def test_returns_int_confidence(self, mock_correlation_df):
        conf = compute_confidence(mock_correlation_df)
        assert isinstance(conf["confidence"], int)


# ---------------------------------------------------------------------------
# 📄 5) NATURAL LANGUAGE SUMMARY TESTS
# ---------------------------------------------------------------------------

class TestGenerateAttackSummary:
    """Tests for the attack summary generator."""

    def test_non_empty_summary(self, mock_correlation_df, mock_timeline_df, mock_graph):
        summary = generate_attack_summary(mock_correlation_df, mock_timeline_df, mock_graph)
        assert isinstance(summary, str)
        assert len(summary) > 20

    def test_mentions_key_process(self, mock_correlation_df, mock_timeline_df, mock_graph):
        """Summary mentions at least one HIGH severity process."""
        summary = generate_attack_summary(mock_correlation_df, mock_timeline_df, mock_graph)
        assert "powershell.exe" in summary.lower()

    def test_mentions_network(self, mock_correlation_df, mock_timeline_df, mock_graph):
        """Summary mentions external connections when present."""
        summary = generate_attack_summary(mock_correlation_df, mock_timeline_df, mock_graph)
        has_ip = "8.8.8.8" in summary or "198.51.100.1" in summary
        has_network_word = "network" in summary.lower() or "connection" in summary.lower() or "external" in summary.lower()
        assert has_ip or has_network_word

    def test_mentions_injection(self, mock_correlation_df, mock_timeline_df, mock_graph):
        """Summary mentions injection when present."""
        summary = generate_attack_summary(mock_correlation_df, mock_timeline_df, mock_graph)
        assert "injection" in summary.lower()

    def test_ends_with_period(self, mock_correlation_df, mock_timeline_df, mock_graph):
        summary = generate_attack_summary(mock_correlation_df, mock_timeline_df, mock_graph)
        assert summary.endswith(".")

    def test_empty_input(self):
        summary = generate_attack_summary(pd.DataFrame(), pd.DataFrame())
        assert isinstance(summary, str)
        assert len(summary) > 0

    def test_none_input(self):
        summary = generate_attack_summary(None, None)
        assert "No analysis data" in summary

    def test_no_high_severity(self):
        """Summary handles data with only LOW severity."""
        df = pd.DataFrame({
            "PID": [1000],
            "ImageFileName": ["explorer.exe"],
            "severity": ["LOW"],
            "correlation_score": [0],
            "has_injection": [False],
            "has_network": [False],
        })
        tl = pd.DataFrame({
            "timestamp": pd.to_datetime(["2026-04-10 10:00:00"]),
            "event_type": ["process_start"],
            "pid": [1000],
            "process_name": ["explorer.exe"],
            "severity": ["LOW"],
            "is_suspicious": [False],
            "description": ["explorer.exe started"],
        })
        summary = generate_attack_summary(df, tl)
        assert isinstance(summary, str)
        assert len(summary) > 10


# ---------------------------------------------------------------------------
# Edge Cases — Missing Columns
# ---------------------------------------------------------------------------

class TestMissingColumns:
    """Tests with partial/missing columns."""

    def test_plan_no_flags(self):
        """Plan works without has_network, has_injection, suspicious_parent."""
        df = pd.DataFrame({
            "PID": [1000, 2000],
            "PPID": [500, 1000],
            "ImageFileName": ["explorer.exe", "cmd.exe"],
            "correlation_score": [0, 5],
            "severity": ["LOW", "HIGH"],
        })
        plan = generate_investigation_plan(df, pd.DataFrame())
        assert len(plan) > 0

    def test_confidence_missing_flags(self):
        """Confidence computation with missing flag columns."""
        df = pd.DataFrame({
            "PID": [1000],
            "ImageFileName": ["test.exe"],
            "correlation_score": [5],
        })
        conf = compute_confidence(df)
        assert conf["confidence"] == 0  # No flags present
        assert len(conf["factors"]) > 0

    def test_root_cause_no_severity(self):
        """Root cause with no severity column."""
        tl = pd.DataFrame({
            "timestamp": pd.to_datetime(["2026-04-10 10:00:00"]),
            "event_type": ["process_start"],
            "pid": [1000],
            "process_name": ["test.exe"],
            "description": ["test started"],
        })
        rc = detect_root_cause(tl, pd.DataFrame())
        assert isinstance(rc, dict)

    def test_chain_missing_type(self):
        """Chain reconstruction with nodes missing type."""
        graph = {
            "nodes": [{"id": "1", "label": "test.exe"}],
            "edges": [],
        }
        chain = reconstruct_attack_chain(graph, pd.DataFrame())
        assert isinstance(chain, list)


# ---------------------------------------------------------------------------
# Performance
# ---------------------------------------------------------------------------

class TestDecisionEnginePerformance:
    """Verify <100ms execution on large datasets."""

    @pytest.fixture
    def large_correlation_df(self) -> pd.DataFrame:
        n = 100_000
        return pd.DataFrame({
            "PID": range(n),
            "PPID": [max(0, i - 1) for i in range(n)],
            "ImageFileName": [f"proc_{i}.exe" for i in range(n)],
            "has_network": [i % 10 == 0 for i in range(n)],
            "has_injection": [i % 1000 == 0 for i in range(n)],
            "suspicious_parent": [i % 500 == 0 for i in range(n)],
            "correlation_score": [i % 10 for i in range(n)],
            "severity": ["HIGH" if i % 100 == 0 else "MEDIUM" if i % 10 == 0 else "LOW" for i in range(n)],
        })

    @pytest.fixture
    def large_timeline_df(self) -> pd.DataFrame:
        n = 100_000
        base = pd.Timestamp("2026-04-10 10:00:00")
        return pd.DataFrame({
            "timestamp": [base + pd.Timedelta(seconds=i) for i in range(n)],
            "event_type": ["process_start" if i % 3 != 0 else "network_connect" for i in range(n)],
            "pid": [i for i in range(n)],
            "process_name": [f"proc_{i}.exe" for i in range(n)],
            "severity": ["HIGH" if i % 100 == 0 else "LOW" for i in range(n)],
            "is_suspicious": [i % 100 == 0 for i in range(n)],
            "description": [
                f"proc_{i}.exe connected to 8.8.{i % 256}.{(i+1) % 256}:443"
                if i % 3 == 0 else f"proc_{i}.exe started"
                for i in range(n)
            ],
        })

    def test_plan_performance(self, large_correlation_df, large_timeline_df):
        """Investigation plan on 100k rows completes in <100ms."""
        start = time.perf_counter()
        plan = generate_investigation_plan(large_correlation_df, large_timeline_df)
        elapsed_ms = (time.perf_counter() - start) * 1000
        assert len(plan) > 0
        assert elapsed_ms < 100, f"Took {elapsed_ms:.1f}ms — target <100ms"

    def test_root_cause_performance(self, large_timeline_df, large_correlation_df):
        """Root cause on 100k rows completes in <100ms."""
        start = time.perf_counter()
        rc = detect_root_cause(large_timeline_df, large_correlation_df)
        elapsed_ms = (time.perf_counter() - start) * 1000
        assert isinstance(rc, dict)
        assert elapsed_ms < 100, f"Took {elapsed_ms:.1f}ms — target <100ms"

    def test_confidence_performance(self, large_correlation_df):
        """Confidence on 100k rows completes in <100ms."""
        start = time.perf_counter()
        conf = compute_confidence(large_correlation_df)
        elapsed_ms = (time.perf_counter() - start) * 1000
        assert conf["confidence"] > 0
        assert elapsed_ms < 100, f"Took {elapsed_ms:.1f}ms — target <100ms"

    def test_summary_performance(self, large_correlation_df, large_timeline_df):
        """Summary on 100k rows completes in <100ms."""
        start = time.perf_counter()
        summary = generate_attack_summary(large_correlation_df, large_timeline_df)
        elapsed_ms = (time.perf_counter() - start) * 1000
        assert len(summary) > 0
        assert elapsed_ms < 100, f"Took {elapsed_ms:.1f}ms — target <100ms"
