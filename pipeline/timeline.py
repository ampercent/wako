"""
Timeline Reconstruction Engine
=================================
Converts correlated forensic data (pslist, netscan, malfind) into a
unified, chronologically sorted sequence of events with human-readable
descriptions and suspicion flags.

Performance: Uses vectorized Pandas operations and ``pd.concat``—
no O(n²) loops. Tested for 100k+ events.
"""

import logging
from typing import Dict, List, Optional, Set

import pandas as pd

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Standard output columns for the timeline DataFrame
TIMELINE_COLUMNS = [
    "timestamp", "event_type", "pid", "process_name",
    "severity", "is_suspicious", "description",
]

# Suspicious severity levels
_SUSPICIOUS_SEVERITIES: Set[str] = {"HIGH", "MEDIUM"}

# Candidate timestamp column names (checked in priority order)
_TS_CANDIDATES = ["CreateTime", "Created", "timestamp", "Time", "created"]


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _has_col(df: Optional[pd.DataFrame], col: str) -> bool:
    """Return True if *df* is a non-empty DataFrame containing *col*."""
    return df is not None and not df.empty and col in df.columns


def _find_timestamp_col(df: pd.DataFrame) -> Optional[str]:
    """Return the first matching timestamp column name, or None."""
    for c in _TS_CANDIDATES:
        if c in df.columns:
            return c
    return None


def _safe_to_datetime(series: pd.Series) -> pd.Series:
    """Convert a Series to datetime, coercing errors to NaT."""
    return pd.to_datetime(series, errors="coerce", utc=True)


def _build_pid_name_map(pslist_df: Optional[pd.DataFrame]) -> Dict[int, str]:
    """Build a {PID: process_name} lookup from pslist."""
    if pslist_df is None or pslist_df.empty:
        return {}
    pid_col = "PID" if "PID" in pslist_df.columns else None
    name_col = "ImageFileName" if "ImageFileName" in pslist_df.columns else None
    if pid_col is None or name_col is None:
        return {}
    return dict(zip(pslist_df[pid_col].astype(int), pslist_df[name_col].astype(str)))


def _build_severity_map(
    correlation_df: Optional[pd.DataFrame],
) -> Dict[int, str]:
    """Build a {PID: severity} lookup from the correlation/enriched DF."""
    if correlation_df is None or correlation_df.empty:
        return {}
    pid_col = "PID" if "PID" in correlation_df.columns else None
    sev_col = "severity" if "severity" in correlation_df.columns else None
    if pid_col is None or sev_col is None:
        return {}
    return dict(zip(correlation_df[pid_col].astype(int), correlation_df[sev_col].astype(str)))


# ---------------------------------------------------------------------------
# Event extraction functions
# ---------------------------------------------------------------------------

def _extract_process_events(
    pslist_df: Optional[pd.DataFrame],
    pid_name_map: Dict[int, str],
    severity_map: Dict[int, str],
) -> pd.DataFrame:
    """Extract ``process_start`` events from pslist."""
    if pslist_df is None or pslist_df.empty:
        return pd.DataFrame(columns=TIMELINE_COLUMNS)

    if "PID" not in pslist_df.columns:
        return pd.DataFrame(columns=TIMELINE_COLUMNS)

    ts_col = _find_timestamp_col(pslist_df)
    records: List[dict] = []

    # Vectorized pre-computation
    pids = pslist_df["PID"].astype(int)
    names = pids.map(pid_name_map).fillna(
        pslist_df["ImageFileName"].astype(str) if "ImageFileName" in pslist_df.columns
        else "unknown"
    )
    timestamps = _safe_to_datetime(pslist_df[ts_col]) if ts_col else pd.Series(
        pd.NaT, index=pslist_df.index
    )
    severities = pids.map(severity_map).fillna("LOW")

    df = pd.DataFrame({
        "timestamp": timestamps,
        "event_type": "process_start",
        "pid": pids,
        "process_name": names,
        "severity": severities,
        "description": "",  # filled below
    })

    # Vectorized description
    df["description"] = df["process_name"] + " (PID " + df["pid"].astype(str) + ") started"

    # Add parent info if available
    if "PPID" in pslist_df.columns:
        ppid_names = pslist_df["PPID"].astype(int).map(pid_name_map).fillna("unknown")
        df["description"] = df["description"] + ", spawned by " + ppid_names

    df["description"] = df["description"] + "."

    return df


def _extract_network_events(
    netscan_df: Optional[pd.DataFrame],
    pid_name_map: Dict[int, str],
    severity_map: Dict[int, str],
) -> pd.DataFrame:
    """Extract ``network_connect`` events from netscan."""
    if netscan_df is None or netscan_df.empty:
        return pd.DataFrame(columns=TIMELINE_COLUMNS)

    if "PID" not in netscan_df.columns:
        return pd.DataFrame(columns=TIMELINE_COLUMNS)

    ts_col = _find_timestamp_col(netscan_df)
    pids = netscan_df["PID"].astype(int)
    names = pids.map(pid_name_map).fillna(
        netscan_df["Owner"].astype(str) if "Owner" in netscan_df.columns else "unknown"
    )
    timestamps = _safe_to_datetime(netscan_df[ts_col]) if ts_col else pd.Series(
        pd.NaT, index=netscan_df.index
    )
    severities = pids.map(severity_map).fillna("LOW")

    # Build description parts vectorized
    foreign = netscan_df["ForeignAddr"].astype(str) if "ForeignAddr" in netscan_df.columns else pd.Series("unknown", index=netscan_df.index)
    foreign_port = netscan_df["ForeignPort"].astype(str) if "ForeignPort" in netscan_df.columns else pd.Series("", index=netscan_df.index)
    state = netscan_df["State"].astype(str) if "State" in netscan_df.columns else pd.Series("", index=netscan_df.index)
    proto = netscan_df["Proto"].astype(str) if "Proto" in netscan_df.columns else pd.Series("", index=netscan_df.index)

    # Format: "msedge.exe connected to 142.250.80.46:443 (ESTABLISHED, TCPv4)."
    desc = names + " (PID " + pids.astype(str) + ") connected to " + foreign
    # Add port if present and non-empty
    has_port = foreign_port.str.strip().ne("") & foreign_port.ne("0")
    desc = desc.where(~has_port, desc + ":" + foreign_port)
    desc = desc + " (" + state + ", " + proto + ")."

    df = pd.DataFrame({
        "timestamp": timestamps,
        "event_type": "network_connect",
        "pid": pids,
        "process_name": names,
        "severity": severities,
        "description": desc,
    })

    return df


def _extract_injection_events(
    malfind_df: Optional[pd.DataFrame],
    pid_name_map: Dict[int, str],
    severity_map: Dict[int, str],
) -> pd.DataFrame:
    """Extract ``injection`` events from malfind."""
    if malfind_df is None or malfind_df.empty:
        return pd.DataFrame(columns=TIMELINE_COLUMNS)

    if "PID" not in malfind_df.columns:
        return pd.DataFrame(columns=TIMELINE_COLUMNS)

    ts_col = _find_timestamp_col(malfind_df)
    pids = malfind_df["PID"].astype(int)

    # Process name: try "Process" first (malfind column), then PID lookup
    if "Process" in malfind_df.columns:
        names = malfind_df["Process"].astype(str)
        # Fill blanks via PID map
        mask = names.isin(["", "nan", "None", "unknown"])
        names = names.where(~mask, pids.map(pid_name_map).fillna("unknown"))
    else:
        names = pids.map(pid_name_map).fillna("unknown")

    timestamps = _safe_to_datetime(malfind_df[ts_col]) if ts_col else pd.Series(
        pd.NaT, index=malfind_df.index
    )
    severities = pids.map(severity_map).fillna("HIGH")  # Injection defaults HIGH

    # Protection details
    protection = (
        malfind_df["Protection"].astype(str)
        if "Protection" in malfind_df.columns
        else pd.Series("unknown", index=malfind_df.index)
    )

    desc = (
        "Memory injection detected in " + names
        + " (PID " + pids.astype(str) + ")"
        + ", protection: " + protection + "."
    )

    df = pd.DataFrame({
        "timestamp": timestamps,
        "event_type": "injection",
        "pid": pids,
        "process_name": names,
        "severity": severities,
        "description": desc,
    })

    return df


# ---------------------------------------------------------------------------
# Description generator (standalone, for custom rows)
# ---------------------------------------------------------------------------

def generate_event_description(row: pd.Series) -> str:
    """
    Generate a concise description string for a single timeline event row.

    Parameters
    ----------
    row : pd.Series
        A row containing at least ``event_type``, ``pid``, ``process_name``.

    Returns
    -------
    str
        Human-readable event description.
    """
    event_type = str(row.get("event_type", "unknown"))
    name = str(row.get("process_name", "unknown"))
    pid = row.get("pid", "?")

    if event_type == "process_start":
        parent = row.get("parent_name", row.get("PPID", ""))
        base = f"{name} (PID {pid}) started"
        if parent and str(parent) not in ("", "nan", "None", "unknown"):
            base += f", spawned by {parent}"
        return base + "."

    if event_type == "network_connect":
        foreign = row.get("ForeignAddr", row.get("foreign_addr", "unknown"))
        port = row.get("ForeignPort", row.get("foreign_port", ""))
        state = row.get("State", row.get("state", ""))
        addr_str = str(foreign)
        if port and str(port) not in ("", "0", "nan"):
            addr_str += f":{port}"
        desc = f"{name} (PID {pid}) connected to {addr_str}"
        if state:
            desc += f" ({state})"
        return desc + "."

    if event_type == "injection":
        prot = row.get("Protection", row.get("protection", ""))
        desc = f"Memory injection detected in {name} (PID {pid})"
        if prot and str(prot) not in ("", "nan", "None"):
            desc += f", protection: {prot}"
        return desc + "."

    return f"Event '{event_type}' on {name} (PID {pid})."


# ---------------------------------------------------------------------------
# Core: build_timeline
# ---------------------------------------------------------------------------

def build_timeline(
    pslist_df: Optional[pd.DataFrame] = None,
    netscan_df: Optional[pd.DataFrame] = None,
    malfind_df: Optional[pd.DataFrame] = None,
    correlation_df: Optional[pd.DataFrame] = None,
) -> pd.DataFrame:
    """
    Build a unified, chronologically sorted timeline of forensic events.

    Parameters
    ----------
    pslist_df : pd.DataFrame, optional
        Process list (PID, ImageFileName, CreateTime, PPID).
    netscan_df : pd.DataFrame, optional
        Network connections (PID, ForeignAddr, State, Created).
    malfind_df : pd.DataFrame, optional
        Memory injection indicators (PID, Process, Protection).
    correlation_df : pd.DataFrame, optional
        Enriched DataFrame with ``severity`` column (from risk scoring).

    Returns
    -------
    pd.DataFrame
        Unified timeline sorted by timestamp ascending. Events with
        missing timestamps are placed at the end.
    """
    # Lookups
    pid_name_map = _build_pid_name_map(pslist_df)
    severity_map = _build_severity_map(correlation_df)

    # Extract events from each source
    frames: List[pd.DataFrame] = [
        _extract_process_events(pslist_df, pid_name_map, severity_map),
        _extract_network_events(netscan_df, pid_name_map, severity_map),
        _extract_injection_events(malfind_df, pid_name_map, severity_map),
    ]

    # Filter out empty frames
    frames = [f for f in frames if not f.empty]

    if not frames:
        logger.warning("No events to build timeline from.")
        return pd.DataFrame(columns=TIMELINE_COLUMNS)

    # Concatenate
    timeline = pd.concat(frames, ignore_index=True)

    # Ensure timestamp column is datetime
    if "timestamp" in timeline.columns:
        timeline["timestamp"] = pd.to_datetime(
            timeline["timestamp"], errors="coerce", utc=True
        )

    # Suspicion flag (vectorized)
    if "severity" in timeline.columns:
        timeline["is_suspicious"] = timeline["severity"].isin(_SUSPICIOUS_SEVERITIES)
    else:
        timeline["is_suspicious"] = False

    # Sort: events with timestamps first (ascending), NaT at end
    timeline = timeline.sort_values(
        "timestamp", ascending=True, na_position="last"
    ).reset_index(drop=True)

    # Ensure all expected columns are present
    for col in TIMELINE_COLUMNS:
        if col not in timeline.columns:
            timeline[col] = None

    return timeline[TIMELINE_COLUMNS]


# ---------------------------------------------------------------------------
# Timeline summary (bonus)
# ---------------------------------------------------------------------------

def summarize_timeline(timeline_df: pd.DataFrame) -> str:
    """
    Return a short narrative summary of the timeline.

    Parameters
    ----------
    timeline_df : pd.DataFrame
        Output of :func:`build_timeline`.

    Returns
    -------
    str
        E.g. "Timeline contains 42 events spanning 2h 15m. 3 suspicious
        processes detected with network activity followed by injection."
    """
    if timeline_df is None or timeline_df.empty:
        return "No events to summarize."

    parts: List[str] = []
    total = len(timeline_df)

    # Event count
    parts.append(f"Timeline contains {total} event{'s' if total != 1 else ''}.")

    # Time span
    if "timestamp" in timeline_df.columns:
        valid_ts = timeline_df["timestamp"].dropna()
        if len(valid_ts) >= 2:
            span = valid_ts.max() - valid_ts.min()
            total_seconds = int(span.total_seconds())
            hours, remainder = divmod(total_seconds, 3600)
            minutes, secs = divmod(remainder, 60)
            if hours > 0:
                parts.append(f"Spanning {hours}h {minutes}m.")
            elif minutes > 0:
                parts.append(f"Spanning {minutes}m {secs}s.")
            else:
                parts.append(f"Spanning {secs}s.")

    # Event type breakdown
    if "event_type" in timeline_df.columns:
        counts = timeline_df["event_type"].value_counts()
        type_parts = []
        for etype, count in counts.items():
            label = {
                "process_start": "process start",
                "network_connect": "network connection",
                "injection": "memory injection",
            }.get(str(etype), str(etype))
            type_parts.append(f"{count} {label}{'s' if count != 1 else ''}")
        parts.append(", ".join(type_parts) + ".")

    # Suspicious chain detection
    if "is_suspicious" in timeline_df.columns:
        suspicious = timeline_df[timeline_df["is_suspicious"]]
        if not suspicious.empty:
            susp_count = len(suspicious)
            parts.append(f"{susp_count} suspicious event{'s' if susp_count != 1 else ''}.")

            # Detect attack chain: process_start → network → injection for same PID
            if "event_type" in suspicious.columns and "pid" in suspicious.columns:
                susp_pids = suspicious["pid"].unique()
                chains: List[str] = []
                for pid in susp_pids[:5]:  # Limit to first 5
                    pid_events = suspicious[suspicious["pid"] == pid]
                    event_types = set(pid_events["event_type"])
                    proc_name = str(pid_events["process_name"].iloc[0])
                    if len(event_types) >= 2:
                        chain_desc = f"{proc_name} (PID {pid})"
                        if "network_connect" in event_types and "injection" in event_types:
                            chains.append(f"{chain_desc} shows network activity and memory injection")
                        elif "network_connect" in event_types:
                            chains.append(f"{chain_desc} shows network activity")
                        elif "injection" in event_types:
                            chains.append(f"{chain_desc} shows memory injection")
                if chains:
                    parts.append("Suspicious chains: " + "; ".join(chains) + ".")

    return " ".join(parts)


# ---------------------------------------------------------------------------
# Example / demo usage
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    from pipeline.correlation import correlate_artifacts
    from pipeline.risk_scoring import enrich_with_explanations

    # ---- Mock data ----
    pslist_df = pd.DataFrame({
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

    netscan_df = pd.DataFrame({
        "PID":         [2780, 2780, 3010, 1234],
        "Proto":       ["TCPv4"] * 4,
        "LocalAddr":   ["192.168.1.10"] * 4,
        "ForeignAddr": ["198.51.100.1", "0.0.0.0", "203.0.113.50", "10.0.0.5"],
        "ForeignPort": [8080, 135, 443, 4444],
        "State":       ["ESTABLISHED", "LISTENING", "ESTABLISHED", "ESTABLISHED"],
        "Owner":       ["BitTorrent.exe", "BitTorrent.exe", "AnyDesk.exe", "powershell.exe"],
        "Created": pd.to_datetime([
            "2026-01-15 08:10:00", "2026-01-15 08:06:30",
            "2026-01-15 10:16:00", "2026-01-15 12:41:30",
        ]),
    })

    malfind_df = pd.DataFrame({
        "PID":        [1234, 5678],
        "Process":    ["powershell.exe", "cmd.exe"],
        "Protection": ["PAGE_EXECUTE_READWRITE"] * 2,
    })

    # ---- Correlate + Enrich ----
    correlated = correlate_artifacts(pslist_df, netscan_df, malfind_df)
    enriched = enrich_with_explanations(correlated)

    # ---- Build timeline ----
    timeline = build_timeline(pslist_df, netscan_df, malfind_df, enriched)

    print("=" * 80)
    print("FORENSIC TIMELINE")
    print("=" * 80)
    for _, row in timeline.iterrows():
        ts = row["timestamp"]
        ts_str = ts.strftime("%Y-%m-%d %H:%M:%S") if pd.notna(ts) else "  [no timestamp]  "
        flag = " 🚨" if row["is_suspicious"] else ""
        print(f"  [{ts_str}] [{row['event_type']:>17}] {row['description']}{flag}")
    print()

    print("=" * 80)
    print("SUMMARY")
    print("=" * 80)
    print(summarize_timeline(timeline))
