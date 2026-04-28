"""
Decision Engine — Analyst Workflow Automation
================================================
Converts existing analysis outputs (correlation, timeline, graph, alerts)
into actionable investigation guidance. Deterministic, <100ms latency,
requires no recomputation of the core pipeline.

All functions consume pre-computed DataFrames/dicts and produce
structured investigation support artifacts.

Performance: Uses vectorized Pandas operations, set lookups, and
dict maps — no row-wise Python loops over full data.
"""

import ipaddress
import logging
import re
from typing import Any, Dict, List, Optional, Set, Tuple

import pandas as pd

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_SEVERITY_RANK: Dict[str, int] = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
_MAX_PLAN_STEPS = 10
_MAX_CHAIN_LENGTH = 8

# RFC 1918 private networks
_PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
]

# Pattern to extract IP:PORT from timeline descriptions
_IP_PORT_RE = re.compile(
    r"connected to\s+"
    r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
    r"(?::(\d+))?"
)


# ---------------------------------------------------------------------------
# 🧰 6) UTILITIES (INTERNAL)
# ---------------------------------------------------------------------------

def is_external_ip(ip: str) -> bool:
    """
    Return True if *ip* is NOT in RFC 1918 / loopback / link-local ranges.

    Handles bare IPs and ``IP:PORT`` strings. Returns False for
    unparseable or special addresses (``0.0.0.0``, ``*``, ``::``, etc.).
    """
    # Strip port / whitespace
    raw = ip.split(":")[0].strip()
    if not raw or raw in ("*", "0.0.0.0", "::", ""):
        return False
    try:
        addr = ipaddress.ip_address(raw)
    except ValueError:
        return False
    for net in _PRIVATE_NETWORKS:
        if addr in net:
            return False
    return True


def extract_ips_from_timeline(timeline_df: pd.DataFrame) -> Set[str]:
    """
    Extract unique ``IP`` or ``IP:PORT`` strings from timeline descriptions.

    Parses the ``description`` column for patterns like
    ``connected to 8.8.8.8:443``.
    """
    ips: Set[str] = set()
    if timeline_df is None or timeline_df.empty:
        return ips
    if "description" not in timeline_df.columns:
        return ips

    # Fully vectorized extraction — filter to network events first for speed
    if "event_type" in timeline_df.columns:
        descs = timeline_df.loc[
            timeline_df["event_type"] == "network_connect", "description"
        ].dropna().astype(str)
    else:
        descs = timeline_df["description"].dropna().astype(str)

    if descs.empty:
        return ips

    extracted = descs.str.extract(_IP_PORT_RE, expand=True)
    if extracted.empty:
        return ips
    valid = extracted.dropna(subset=[0])
    if valid.empty:
        return ips

    # Fully vectorized: build IP:PORT strings without iterrows
    ip_col = valid[0]
    port_col = valid[1]
    has_port = port_col.notna()
    # Build combined strings vectorized
    combined = ip_col.copy()
    if has_port.any():
        combined.loc[has_port] = ip_col.loc[has_port] + ":" + port_col.loc[has_port]
    ips = set(combined.unique())
    return ips


def build_pid_maps(
    correlation_df: pd.DataFrame,
) -> Tuple[Dict[int, str], Dict[int, int], Dict[int, str]]:
    """
    Build lookup dicts from the correlation DataFrame.

    Returns
    -------
    (pid_to_name, pid_to_parent, pid_to_severity)
        Three dicts keyed by PID (int).
    """
    pid_to_name: Dict[int, str] = {}
    pid_to_parent: Dict[int, int] = {}
    pid_to_severity: Dict[int, str] = {}

    if correlation_df is None or correlation_df.empty:
        return pid_to_name, pid_to_parent, pid_to_severity

    if "PID" in correlation_df.columns and "ImageFileName" in correlation_df.columns:
        pid_to_name = dict(zip(
            correlation_df["PID"].astype(int),
            correlation_df["ImageFileName"].astype(str),
        ))
    if "PID" in correlation_df.columns and "PPID" in correlation_df.columns:
        pid_to_parent = dict(zip(
            correlation_df["PID"].astype(int),
            correlation_df["PPID"].astype(int),
        ))
    if "PID" in correlation_df.columns and "severity" in correlation_df.columns:
        pid_to_severity = dict(zip(
            correlation_df["PID"].astype(int),
            correlation_df["severity"].astype(str),
        ))

    return pid_to_name, pid_to_parent, pid_to_severity


def _safe_col(df: Optional[pd.DataFrame], col: str) -> bool:
    """Return True if df is non-empty and contains col."""
    return df is not None and not df.empty and col in df.columns


def _get_external_ips_from_graph(graph: Optional[dict]) -> Set[str]:
    """Extract external IP labels from graph nodes."""
    ips: Set[str] = set()
    if graph is None:
        return ips
    for node in graph.get("nodes", []):
        if node.get("type") in ("network", "ip"):
            label = str(node.get("label", ""))
            raw_ip = label.split(":")[0].strip()
            if is_external_ip(raw_ip):
                ips.add(label)
    return ips


# ---------------------------------------------------------------------------
# 🧭 1) INVESTIGATION PLAN
# ---------------------------------------------------------------------------

def generate_investigation_plan(
    correlation_df: pd.DataFrame,
    timeline_df: pd.DataFrame,
    graph: Optional[dict] = None,
) -> List[Dict[str, Any]]:
    """
    Generate an ordered list of investigation steps.

    Rules
    -----
    * Rank by severity DESC, then correlation_score DESC
    * HIGH severity processes first, then injection, network, unusual parent
    * At least one network-focused step if external IPs exist
    * Cap at 10 steps, unique entities only

    Parameters
    ----------
    correlation_df : pd.DataFrame
        Enriched correlation output with severity, flags, scores.
    timeline_df : pd.DataFrame
        Forensic timeline.
    graph : dict, optional
        Attack graph JSON.

    Returns
    -------
    list[dict]
        Ordered investigation steps.
    """
    if correlation_df is None or correlation_df.empty:
        logger.debug("generate_investigation_plan: empty correlation_df")
        return []

    steps: List[Dict[str, Any]] = []
    seen_entities: Set[str] = set()

    # Build fast column references without copying the full DF
    has_sev = "severity" in correlation_df.columns
    has_score = "correlation_score" in correlation_df.columns
    has_inj = "has_injection" in correlation_df.columns
    has_net = "has_network" in correlation_df.columns
    has_susp = "suspicious_parent" in correlation_df.columns
    has_pid = "PID" in correlation_df.columns
    has_name = "ImageFileName" in correlation_df.columns
    has_ppid = "PPID" in correlation_df.columns

    # Build pid maps once (vectorized dict construction)
    pid_to_name, pid_to_parent, _ = build_pid_maps(correlation_df)

    # Extract external IPs from graph only (lightweight, avoids timeline scan)
    graph_ips = _get_external_ips_from_graph(graph)
    all_external = {ip for ip in graph_ips if is_external_ip(ip.split(":")[0])}

    def _add_step(pid, entity, action, reason, priority):
        if entity in seen_entities or len(steps) >= _MAX_PLAN_STEPS:
            return
        seen_entities.add(entity)
        steps.append({
            "step": len(steps) + 1,
            "pid": int(pid) if pid is not None else None,
            "entity": entity,
            "action": action,
            "reason": reason,
            "priority": priority,
        })

    def _add_from_mask(mask, make_action, make_reason, priority, limit=10):
        """Add steps from boolean mask using .loc and .head() — no copy needed."""
        subset = correlation_df.loc[mask]
        if subset.empty:
            return
        # Sort only the small subset by score descending
        if has_score and len(subset) > 1:
            subset = subset.nlargest(limit, "correlation_score", keep="first")
        else:
            subset = subset.head(limit)
        for pid, name, ppid in zip(
            subset["PID"].astype(int) if has_pid else [0] * len(subset),
            subset["ImageFileName"].astype(str) if has_name else ["unknown"] * len(subset),
            subset["PPID"].astype(int) if has_ppid else [0] * len(subset),
        ):
            _add_step(pid, name, make_action(name, pid, ppid), make_reason(name, pid, ppid), priority)

    # Pass 1: HIGH severity
    if has_sev:
        _add_from_mask(
            correlation_df["severity"] == "HIGH",
            lambda n, p, pp: f"Investigate {n} (PID {p}) immediately",
            lambda n, p, pp: "HIGH severity — critical threat indicators",
            "HIGH",
        )

    # Pass 2: Injection
    if has_inj:
        _add_from_mask(
            correlation_df["has_injection"] == True,
            lambda n, p, pp: f"Analyze memory injection in {n} (PID {p})",
            lambda n, p, pp: "Memory injection (malfind hit) detected — potential code injection or hollowing",
            "HIGH",
        )

    # Pass 3: MEDIUM + network
    if has_sev and has_net:
        _add_from_mask(
            (correlation_df["severity"] == "MEDIUM") & (correlation_df["has_network"] == True),
            lambda n, p, pp: f"Review network connections for {n} (PID {p})",
            lambda n, p, pp: "MEDIUM severity process with active network connections",
            "MEDIUM",
        )

    # Pass 4: Suspicious parent
    if has_susp:
        _add_from_mask(
            correlation_df["suspicious_parent"] == True,
            lambda n, p, pp: f"Examine parent-child relationship: {pid_to_name.get(pp, 'unknown')} → {n}",
            lambda n, p, pp: f"Unusual parent {pid_to_name.get(pp, 'unknown')} for {n} — possible process masquerading",
            "MEDIUM",
        )

    # Pass 5: External IPs
    for ip_str in sorted(all_external):
        _add_step(None, ip_str,
                  f"Check reputation and ownership of external IP {ip_str}",
                  "External network endpoint — verify legitimacy via threat intel",
                  "MEDIUM")

    # Pass 6: Remaining MEDIUM
    if has_sev:
        _add_from_mask(
            correlation_df["severity"] == "MEDIUM",
            lambda n, p, pp: f"Review activity of {n} (PID {p})",
            lambda n, p, pp: "MEDIUM severity — warrants analyst attention",
            "MEDIUM",
        )

    # Renumber steps
    for i, step in enumerate(steps):
        step["step"] = i + 1

    logger.debug(f"Investigation plan: {len(steps)} steps generated")
    return steps


# ---------------------------------------------------------------------------
# 🎯 2) ROOT CAUSE DETECTION
# ---------------------------------------------------------------------------

def detect_root_cause(
    timeline_df: pd.DataFrame,
    correlation_df: pd.DataFrame,
) -> Dict[str, Any]:
    """
    Detect the likely root cause / entry point of the attack.

    Logic
    -----
    * ``entry_process``: earliest process in timeline that is an ancestor
      of any suspicious chain
    * ``first_suspicious``: earliest event with HIGH/MEDIUM severity,
      injection, or external network connection

    Parameters
    ----------
    timeline_df : pd.DataFrame
        Forensic timeline with timestamps.
    correlation_df : pd.DataFrame
        Enriched correlation data.

    Returns
    -------
    dict
        Keys: entry_process, first_suspicious, entry_pid,
        first_suspicious_pid, reason.
    """
    result: Dict[str, Any] = {
        "entry_process": None,
        "first_suspicious": None,
        "entry_pid": None,
        "first_suspicious_pid": None,
        "reason": "Insufficient data for root cause analysis.",
    }

    if timeline_df is None or timeline_df.empty:
        return result

    if "timestamp" not in timeline_df.columns:
        return result

    # Parse timestamps — skip if already datetime to avoid re-parsing cost
    if pd.api.types.is_datetime64_any_dtype(timeline_df["timestamp"]):
        ts = timeline_df["timestamp"]
    else:
        ts = pd.to_datetime(timeline_df["timestamp"], errors="coerce")
    valid_mask = ts.notna()
    if not valid_mask.any():
        return result

    # --- Build suspicious mask using vectorized ops ---
    suspicious_mask = pd.Series(False, index=timeline_df.index)

    if "severity" in timeline_df.columns:
        suspicious_mask |= timeline_df["severity"].isin(["HIGH", "MEDIUM"])
    if "is_suspicious" in timeline_df.columns:
        suspicious_mask |= timeline_df["is_suspicious"].astype(bool)

    # Check for external network connections (vectorized, no apply)
    if "description" in timeline_df.columns and "event_type" in timeline_df.columns:
        net_mask = timeline_df["event_type"] == "network_connect"
        if net_mask.any():
            net_descs = timeline_df.loc[net_mask, "description"].astype(str)
            # Extract IPs vectorized
            ip_series = net_descs.str.extract(r"connected to\s+(\d+\.\d+\.\d+\.\d+)", expand=False)
            valid_ips = ip_series.dropna()
            if not valid_ips.empty:
                # Batch IP check — build set of IPs first, check once
                unique_ips = valid_ips.unique()
                external_set = {ip for ip in unique_ips if is_external_ip(ip)}
                if external_set:
                    external_idx = valid_ips[valid_ips.isin(external_set)].index
                    suspicious_mask.loc[external_idx] = True

    # Check injection from correlation_df
    injection_pids: Set[int] = set()
    if _safe_col(correlation_df, "has_injection") and _safe_col(correlation_df, "PID"):
        injection_pids = set(
            correlation_df.loc[correlation_df["has_injection"] == True, "PID"]
            .astype(int)
        )
    if injection_pids and "pid" in timeline_df.columns:
        suspicious_mask |= timeline_df["pid"].astype(int).isin(injection_pids)

    # Combine with valid timestamp mask
    susp_and_valid = suspicious_mask & valid_mask

    if susp_and_valid.any():
        # Find earliest suspicious event by timestamp (no sort needed)
        susp_ts = ts[susp_and_valid]
        first_idx = susp_ts.idxmin()
        first_susp = timeline_df.loc[first_idx]
        result["first_suspicious"] = str(first_susp.get("process_name", "unknown"))
        result["first_suspicious_pid"] = int(first_susp["pid"]) if "pid" in first_susp.index else None

    # --- Entry process (ancestor of suspicious chain) ---
    # Only trace ancestors of the EARLIEST suspicious PIDs (not all — too expensive)
    if susp_and_valid.any() and "pid" in timeline_df.columns and \
       _safe_col(correlation_df, "PID") and _safe_col(correlation_df, "PPID"):
        # Get the earliest few suspicious PIDs by timestamp
        susp_ts_for_pids = ts[susp_and_valid]
        earliest_idx = susp_ts_for_pids.nsmallest(10).index
        suspicious_pids = set(timeline_df.loc[earliest_idx, "pid"].dropna().astype(int).unique())

        # Build parent lookup lazily (only PID→PPID, not full maps)
        pid_to_parent = dict(zip(
            correlation_df["PID"].astype(int),
            correlation_df["PPID"].astype(int),
        ))

        # Walk up parent chains to find all ancestors
        ancestor_pids = set(suspicious_pids)
        for spid in suspicious_pids:
            current = spid
            depth = 0
            while current in pid_to_parent and depth < 20:
                parent = pid_to_parent[current]
                if parent == current:
                    break
                ancestor_pids.add(parent)
                current = parent
                depth += 1

        # Find earliest process_start among ancestors (no sort, use idxmin)
        if "event_type" in timeline_df.columns:
            starts_mask = (timeline_df["event_type"] == "process_start") & \
                          (timeline_df["pid"].astype(int).isin(ancestor_pids)) & valid_mask
            if starts_mask.any():
                entry_idx = ts[starts_mask].idxmin()
                entry = timeline_df.loc[entry_idx]
                result["entry_process"] = str(entry.get("process_name", "unknown"))
                result["entry_pid"] = int(entry["pid"])

    # Build reason
    reasons: List[str] = []
    if result["entry_process"]:
        reasons.append(f"Entry point: {result['entry_process']} (PID {result['entry_pid']})")
    if result["first_suspicious"]:
        reasons.append(
            f"First suspicious activity: {result['first_suspicious']} "
            f"(PID {result['first_suspicious_pid']})"
        )
    result["reason"] = "; ".join(reasons) if reasons else "No suspicious activity detected."

    logger.debug(f"Root cause: {result['entry_process']} → {result['first_suspicious']}")
    return result


# ---------------------------------------------------------------------------
# 🔗 3) ATTACK CHAIN RECONSTRUCTION
# ---------------------------------------------------------------------------

def reconstruct_attack_chain(
    graph: Optional[dict],
    timeline_df: pd.DataFrame,
) -> List[str]:
    """
    Reconstruct the ordered attack chain from entry to impact.

    Logic
    -----
    * Start from the root cause (earliest suspicious process)
    * Follow parent_child edges forward through the graph
    * Append network_connection targets (external IPs)
    * Prefer timeline order to break ties
    * Limit to 8 nodes

    Parameters
    ----------
    graph : dict
        Attack graph with nodes and edges.
    timeline_df : pd.DataFrame
        Forensic timeline for ordering.

    Returns
    -------
    list[str]
        Ordered entity labels (process names and ``IP:PORT``).
    """
    if graph is None:
        return []

    nodes = graph.get("nodes", [])
    edges = graph.get("edges", [])

    if not nodes:
        return []

    # Build lookup structures
    id_to_label: Dict[str, str] = {}
    id_to_type: Dict[str, str] = {}
    id_to_severity_rank: Dict[str, int] = {}

    for node in nodes:
        nid = str(node.get("id", ""))
        id_to_label[nid] = str(node.get("label", nid))
        id_to_type[nid] = str(node.get("type", ""))
        sev = str(node.get("severity", "LOW"))
        id_to_severity_rank[nid] = _SEVERITY_RANK.get(sev, 2)

    # Adjacency: source → [targets]
    children: Dict[str, List[str]] = {}
    net_targets: Dict[str, List[str]] = {}
    for edge in edges:
        src = str(edge.get("source", ""))
        tgt = str(edge.get("target", ""))
        etype = str(edge.get("type", ""))
        if etype == "parent_child":
            children.setdefault(src, []).append(tgt)
        elif etype in ("network_connection", "network"):
            net_targets.setdefault(src, []).append(tgt)

    # Build timeline ordering for tie-breaking (vectorized)
    pid_order: Dict[int, int] = {}
    if timeline_df is not None and not timeline_df.empty and "pid" in timeline_df.columns:
        tl = timeline_df.copy()
        if "timestamp" in tl.columns:
            tl["timestamp"] = pd.to_datetime(tl["timestamp"], errors="coerce")
            tl = tl.sort_values("timestamp", ascending=True, na_position="last")
        # Use groupby first occurrence instead of row-wise loop
        tl_pids = tl["pid"].dropna()
        try:
            first_occ = tl_pids.astype(int).drop_duplicates(keep="first")
            pid_order = {pid: i for i, pid in enumerate(first_occ)}  
        except (ValueError, TypeError):
            pass

    def _node_order(nid: str) -> int:
        """Sort key: severity rank, then timeline position."""
        sev = id_to_severity_rank.get(nid, 2)
        # Extract PID from node id like "pid_1234"
        try:
            pid = int(nid.split("_")[-1])
            tl_pos = pid_order.get(pid, 9999)
        except (ValueError, IndexError):
            tl_pos = 9999
        return sev * 10000 + tl_pos

    # Find starting node: most suspicious process (lowest severity rank, earliest timeline)
    process_nodes = [nid for nid, ntype in id_to_type.items() if ntype == "process"]
    if not process_nodes:
        return []

    process_nodes.sort(key=_node_order)
    start = process_nodes[0]

    # BFS forward through parent_child edges
    chain_ids: List[str] = []
    visited: Set[str] = set()
    queue = [start]

    while queue and len(chain_ids) < _MAX_CHAIN_LENGTH:
        node = queue.pop(0)
        if node in visited:
            continue
        visited.add(node)

        if id_to_type.get(node) == "process":
            chain_ids.append(node)

        # Follow children, sorted by timeline order
        kids = children.get(node, [])
        kids.sort(key=_node_order)
        queue.extend(kids)

    # Append network targets for processes in the chain
    for nid in list(chain_ids):
        if len(chain_ids) >= _MAX_CHAIN_LENGTH:
            break
        for net_id in net_targets.get(nid, []):
            if net_id not in visited and len(chain_ids) < _MAX_CHAIN_LENGTH:
                visited.add(net_id)
                chain_ids.append(net_id)

    # Convert to labels
    chain = [id_to_label.get(nid, nid) for nid in chain_ids]

    logger.debug(f"Attack chain: {chain}")
    return chain


# ---------------------------------------------------------------------------
# 🧠 4) CONFIDENCE SCORING
# ---------------------------------------------------------------------------

def compute_confidence(
    correlation_df: pd.DataFrame,
    graph: Optional[dict] = None,
) -> Dict[str, Any]:
    """
    Compute a confidence score (0–100) for the investigation findings.

    Scoring Rules
    -------------
    * Memory injection present (any PID) → +30
    * External (non-RFC1918) IP present → +25
    * Suspicious parent relationship present → +20
    * ≥2 indicators co-occur in same PID → +25
    * Clamped to [0, 100]

    Parameters
    ----------
    correlation_df : pd.DataFrame
        Enriched correlation data.
    graph : dict, optional
        Attack graph for network endpoint analysis.

    Returns
    -------
    dict
        ``confidence`` (int) and ``factors`` (list of name/score dicts).
    """
    factors: List[Dict[str, Any]] = []
    total = 0

    if correlation_df is None or correlation_df.empty:
        return {"confidence": 0, "factors": []}

    # Factor 1: Memory injection
    has_injection = False
    if _safe_col(correlation_df, "has_injection"):
        has_injection = bool(correlation_df["has_injection"].any())
    injection_score = 30 if has_injection else 0
    factors.append({"name": "memory_injection", "score": injection_score})
    total += injection_score

    # Factor 2: External network
    has_external = False
    if _safe_col(correlation_df, "has_network"):
        if graph is not None:
            ext_ips = _get_external_ips_from_graph(graph)
            has_external = len(ext_ips) > 0
        # If no graph, check if any process has network flag (best effort)
        if not has_external:
            has_external = bool(correlation_df["has_network"].any())
    network_score = 25 if has_external else 0
    factors.append({"name": "external_network", "score": network_score})
    total += network_score

    # Factor 3: Abnormal parent
    has_susp_parent = False
    if _safe_col(correlation_df, "suspicious_parent"):
        has_susp_parent = bool(correlation_df["suspicious_parent"].any())
    parent_score = 20 if has_susp_parent else 0
    factors.append({"name": "abnormal_parent", "score": parent_score})
    total += parent_score

    # Factor 4: Multi-indicator (≥2 flags on same PID)
    multi_indicator = False
    flag_cols = ["has_network", "has_injection", "suspicious_parent"]
    existing_flags = [c for c in flag_cols if c in correlation_df.columns]
    if len(existing_flags) >= 2:
        flag_sum = correlation_df[existing_flags].astype(int).sum(axis=1)
        multi_indicator = bool((flag_sum >= 2).any())
    multi_score = 25 if multi_indicator else 0
    factors.append({"name": "multi_indicator", "score": multi_score})
    total += multi_score

    confidence = min(total, 100)

    logger.debug(f"Confidence: {confidence} (factors: {factors})")
    return {"confidence": confidence, "factors": factors}


# ---------------------------------------------------------------------------
# 📄 5) NATURAL LANGUAGE SUMMARY
# ---------------------------------------------------------------------------

def generate_attack_summary(
    correlation_df: pd.DataFrame,
    timeline_df: pd.DataFrame,
    graph: Optional[dict] = None,
) -> str:
    """
    Generate a concise natural-language summary of the investigation findings.

    Mentions entry process (if determinable), key HIGH-severity processes,
    external network activity, and injection indicators.

    Parameters
    ----------
    correlation_df : pd.DataFrame
        Enriched correlation data.
    timeline_df : pd.DataFrame
        Forensic timeline.
    graph : dict, optional
        Attack graph.

    Returns
    -------
    str
        1–3 sentence investigation summary.
    """
    if correlation_df is None or correlation_df.empty:
        return "No analysis data available to generate a summary."

    parts: List[str] = []

    # Detect root cause for entry mention
    root = detect_root_cause(timeline_df, correlation_df)

    # Identify key HIGH processes
    high_procs: List[str] = []
    if _safe_col(correlation_df, "severity") and _safe_col(correlation_df, "ImageFileName"):
        high_df = correlation_df[correlation_df["severity"] == "HIGH"]
        if not high_df.empty:
            # Sort by score descending
            if "correlation_score" in high_df.columns:
                high_df = high_df.sort_values("correlation_score", ascending=False)
            high_procs = high_df["ImageFileName"].astype(str).head(2).tolist()

    # Detect external IPs — prefer graph (O(n) on few nodes) over timeline
    graph_ips = _get_external_ips_from_graph(graph)
    all_ext = sorted({ip for ip in graph_ips if is_external_ip(ip.split(":")[0])})
    if not all_ext:
        # Fall back to timeline only if graph has no IPs
        external_ips = extract_ips_from_timeline(timeline_df)
        all_ext = sorted({ip for ip in external_ips if is_external_ip(ip.split(":")[0])})

    # Detect injection
    has_injection = False
    injection_procs: List[str] = []
    if _safe_col(correlation_df, "has_injection") and _safe_col(correlation_df, "ImageFileName"):
        inj_df = correlation_df[correlation_df["has_injection"] == True]
        has_injection = not inj_df.empty
        injection_procs = inj_df["ImageFileName"].astype(str).head(2).tolist()

    # Build narrative
    if root.get("entry_process") and high_procs:
        entry = root["entry_process"]
        chain_desc = f"A suspicious chain was identified where {entry}"
        if high_procs and high_procs[0].lower() != entry.lower():
            chain_desc += f" led to {high_procs[0]}"
            if len(high_procs) > 1:
                chain_desc += f" and {high_procs[1]}"
        parts.append(chain_desc)
    elif high_procs:
        procs_str = " and ".join(high_procs[:2])
        parts.append(f"High-risk activity detected involving {procs_str}")
    else:
        # No HIGH severity — mention medium
        med_procs: List[str] = []
        if _safe_col(correlation_df, "severity"):
            med_df = correlation_df[correlation_df["severity"] == "MEDIUM"]
            if not med_df.empty:
                med_procs = med_df["ImageFileName"].astype(str).head(2).tolist()
        if med_procs:
            parts.append(f"Suspicious activity detected involving {' and '.join(med_procs)}")
        else:
            parts.append("Analysis completed with no high-severity indicators")

    # Network mention
    if all_ext:
        ip_mentions = ", ".join(all_ext[:2])
        parts.append(f"with external connections to {ip_mentions}")

    # Injection mention
    if has_injection and injection_procs:
        inj_str = " and ".join(injection_procs[:2])
        parts.append(f"and {inj_str} exhibiting memory injection behavior")
    elif has_injection:
        parts.append("with memory injection indicators detected")

    # Join with appropriate connectors
    if len(parts) == 1:
        summary = parts[0] + "."
    elif len(parts) == 2:
        summary = f"{parts[0]}, {parts[1]}."
    else:
        summary = f"{parts[0]}, {parts[1]}, {parts[2]}."

    logger.debug(f"Attack summary generated ({len(summary)} chars)")
    return summary


# ---------------------------------------------------------------------------
# Example / demo usage
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    # Mock data
    corr_df = pd.DataFrame({
        "PID": [1000, 2010, 3010, 4010, 5010],
        "PPID": [500, 1000, 2010, 2010, 1000],
        "ImageFileName": ["explorer.exe", "certutil.exe", "powershell.exe", "cmd.exe", "chrome.exe"],
        "has_network": [False, True, True, False, True],
        "has_injection": [False, False, True, False, False],
        "suspicious_parent": [False, False, True, True, False],
        "correlation_score": [0, 3, 8, 5, 2],
        "severity": ["LOW", "MEDIUM", "HIGH", "MEDIUM", "LOW"],
    })

    tl_df = pd.DataFrame({
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
            "Memory injection detected in powershell.exe (PID 3010), protection: PAGE_EXECUTE_READWRITE.",
        ],
    })

    graph_data = {
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

    print("=" * 70)
    print("INVESTIGATION PLAN")
    print("=" * 70)
    plan = generate_investigation_plan(corr_df, tl_df, graph_data)
    for step in plan:
        print(f"  [{step['priority']:>6}] Step {step['step']}: {step['action']}")
        print(f"          → {step['reason']}")

    print("\n" + "=" * 70)
    print("ROOT CAUSE")
    print("=" * 70)
    rc = detect_root_cause(tl_df, corr_df)
    for k, v in rc.items():
        print(f"  {k}: {v}")

    print("\n" + "=" * 70)
    print("ATTACK CHAIN")
    print("=" * 70)
    chain = reconstruct_attack_chain(graph_data, tl_df)
    print("  " + " → ".join(chain))

    print("\n" + "=" * 70)
    print("CONFIDENCE")
    print("=" * 70)
    conf = compute_confidence(corr_df, graph_data)
    print(f"  Score: {conf['confidence']}%")
    for f in conf["factors"]:
        print(f"    {f['name']}: +{f['score']}")

    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    summary = generate_attack_summary(corr_df, tl_df, graph_data)
    print(f"  {summary}")
