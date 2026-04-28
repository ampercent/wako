"""
Risk Scoring and Explanation Layer
====================================
Builds on the correlation engine to provide investigator-friendly
severity classifications, human-readable explanations, alert filtering,
and investigation summaries.

Performance: Uses vectorized Pandas operations wherever possible.
Designed for 100k+ row DataFrames.
"""

import logging
from typing import List, Optional

import pandas as pd

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Severity thresholds (configurable)
_HIGH_THRESHOLD: int = 6
_MEDIUM_THRESHOLD: int = 3

# Known abused binaries for richer explanations
_KNOWN_ABUSED_BINARIES = {
    "powershell.exe", "cmd.exe", "mshta.exe", "regsvr32.exe",
    "certutil.exe", "bitsadmin.exe", "wscript.exe", "cscript.exe",
    "rundll32.exe", "netcat.exe", "ncat.exe",
}

# Severity sort order (HIGH first)
_SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}

# Columns required in the correlated DataFrame
_REQUIRED_COLUMNS = {"PID", "ImageFileName", "correlation_score"}


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _safe_get(row: pd.Series, col: str, default=None):
    """Safely retrieve a value from a Series, returning *default* if absent or null."""
    try:
        val = row.get(col, default)
        if pd.isna(val):
            return default
        return val
    except (TypeError, KeyError):
        return default


def _has_column(df: pd.DataFrame, col: str) -> bool:
    """Check whether a column exists and the DataFrame is non-empty."""
    return not df.empty and col in df.columns


# ---------------------------------------------------------------------------
# 1. Severity classification
# ---------------------------------------------------------------------------

def classify_severity(score: int) -> str:
    """
    Map a numeric correlation score to a severity label.

    Parameters
    ----------
    score : int
        The correlation score for a process.

    Returns
    -------
    str
        ``"HIGH"`` if *score* >= 6, ``"MEDIUM"`` if >= 3, else ``"LOW"``.
    """
    if score >= _HIGH_THRESHOLD:
        return "HIGH"
    if score >= _MEDIUM_THRESHOLD:
        return "MEDIUM"
    return "LOW"


def _classify_severity_vectorized(scores: pd.Series) -> pd.Series:
    """
    Vectorized version of :func:`classify_severity` using ``pd.cut``.
    """
    return pd.cut(
        scores,
        bins=[-float("inf"), _MEDIUM_THRESHOLD - 1, _HIGH_THRESHOLD - 1, float("inf")],
        labels=["LOW", "MEDIUM", "HIGH"],
        right=True,
    ).astype(str)


# ---------------------------------------------------------------------------
# 2. Row-level explanation engine
# ---------------------------------------------------------------------------

def explain_process_row(row: pd.Series) -> str:
    """
    Generate a concise, natural-language explanation for a single process row.

    Parameters
    ----------
    row : pd.Series
        A row from the enriched/correlated DataFrame.

    Returns
    -------
    str
        A human-readable explanation string.  Returns a safe fallback if
        required fields are missing or null.
    """
    name = str(_safe_get(row, "ImageFileName", "unknown"))
    pid = _safe_get(row, "PID", "?")
    parent = str(_safe_get(row, "parent_name", _safe_get(row, "PPID", "unknown")))

    indicators: List[str] = []

    # Network activity
    if _safe_get(row, "has_network", False):
        indicators.append("initiated a network connection")

    # Memory injection
    if _safe_get(row, "has_injection", False):
        indicators.append("shows signs of memory injection")

    # Suspicious parent
    if _safe_get(row, "suspicious_parent", False):
        indicators.append(f"was spawned by {parent}, which is unusual")

    # Known abused binary
    if name.lower().strip() in _KNOWN_ABUSED_BINARIES:
        indicators.append("is a known abused system binary")

    # Build sentence
    if not indicators:
        return f"{name} (PID {pid}) shows no suspicious indicators."

    # Join with commas + "and" for the last item
    if len(indicators) == 1:
        joined = indicators[0]
    elif len(indicators) == 2:
        joined = f"{indicators[0]} and {indicators[1]}"
    else:
        joined = ", ".join(indicators[:-1]) + f", and {indicators[-1]}"

    return f"{name} (PID {pid}) {joined}."


# ---------------------------------------------------------------------------
# 3. Data enrichment
# ---------------------------------------------------------------------------

def enrich_with_explanations(df: pd.DataFrame) -> pd.DataFrame:
    """
    Add ``severity`` and ``explanation`` columns to a correlated DataFrame.

    Parameters
    ----------
    df : pd.DataFrame
        Output of :func:`pipeline.correlation.correlate_artifacts`.
        Must contain at least ``PID``, ``ImageFileName``, and
        ``correlation_score``.

    Returns
    -------
    pd.DataFrame
        The original DataFrame with two new columns, sorted by severity
        (HIGH → LOW) then by ``correlation_score`` descending.
    """
    if df is None or df.empty:
        logger.warning("Empty DataFrame — returning empty enriched result.")
        return pd.DataFrame(columns=[
            "PID", "ImageFileName", "correlation_score",
            "severity", "explanation",
        ])

    # Validate required columns
    missing = _REQUIRED_COLUMNS - set(df.columns)
    if missing:
        logger.error(f"Missing required columns: {missing}")
        return df.copy()

    enriched = df.copy()

    # --- Severity (vectorized) ---
    enriched["severity"] = _classify_severity_vectorized(
        enriched["correlation_score"]
    )

    # --- Explanation (row-wise — unavoidable for NL generation) ---
    enriched["explanation"] = enriched.apply(explain_process_row, axis=1)

    # --- Sort: severity rank first, then score descending ---
    enriched["_sev_order"] = enriched["severity"].map(_SEVERITY_ORDER)
    enriched = (
        enriched
        .sort_values(["_sev_order", "correlation_score"], ascending=[True, False])
        .drop(columns=["_sev_order"])
        .reset_index(drop=True)
    )

    return enriched


# ---------------------------------------------------------------------------
# 4. Alert filtering
# ---------------------------------------------------------------------------

def generate_alerts(df: pd.DataFrame) -> pd.DataFrame:
    """
    Filter the enriched DataFrame to HIGH and MEDIUM severity only.

    Parameters
    ----------
    df : pd.DataFrame
        Output of :func:`enrich_with_explanations` (must have a
        ``severity`` column).

    Returns
    -------
    pd.DataFrame
        Subset with columns: ``PID``, ``ImageFileName``, ``severity``,
        ``correlation_score``, ``explanation``.
    """
    if df is None or df.empty or "severity" not in df.columns:
        logger.warning("Cannot generate alerts — no severity column.")
        return pd.DataFrame(columns=[
            "PID", "ImageFileName", "severity",
            "correlation_score", "explanation",
        ])

    alert_cols = ["PID", "ImageFileName", "severity",
                  "correlation_score", "explanation"]
    # Keep only columns that exist
    available = [c for c in alert_cols if c in df.columns]

    alerts = df[df["severity"].isin(["HIGH", "MEDIUM"])].copy()
    return alerts[available].reset_index(drop=True)


# ---------------------------------------------------------------------------
# 5. Investigation summary (bonus)
# ---------------------------------------------------------------------------

def explain_summary(df: pd.DataFrame) -> str:
    """
    Return a short investigation summary string.

    Parameters
    ----------
    df : pd.DataFrame
        The enriched DataFrame (must have ``severity``, ``has_injection``,
        ``suspicious_parent`` columns).

    Returns
    -------
    str
        E.g. "3 high-risk processes detected. 2 involve memory injection.
        1 process shows suspicious parent-child behavior."
    """
    if df is None or df.empty:
        return "No processes to analyze."

    parts: List[str] = []

    # Severity counts
    if "severity" in df.columns:
        high = int((df["severity"] == "HIGH").sum())
        med = int((df["severity"] == "MEDIUM").sum())
        total_flagged = high + med

        if high > 0:
            parts.append(f"{high} high-risk process{'es' if high != 1 else ''} detected.")
        if med > 0:
            parts.append(f"{med} medium-risk process{'es' if med != 1 else ''} detected.")
        if total_flagged == 0:
            parts.append("No high or medium-risk processes detected.")

    # Injection count
    if _has_column(df, "has_injection"):
        inj = int(df["has_injection"].sum())
        if inj > 0:
            parts.append(f"{inj} involve{'s' if inj == 1 else ''} memory injection.")

    # Suspicious parent count
    if _has_column(df, "suspicious_parent"):
        sp = int(df["suspicious_parent"].sum())
        if sp > 0:
            parts.append(
                f"{sp} process{'es' if sp != 1 else ''} show{'s' if sp == 1 else ''} "
                f"suspicious parent-child behavior."
            )

    # Network count
    if _has_column(df, "has_network"):
        net = int(df["has_network"].sum())
        if net > 0:
            parts.append(f"{net} process{'es' if net != 1 else ''} ha{'s' if net == 1 else 've'} network activity.")

    return " ".join(parts) if parts else "No analysis data available."


# ---------------------------------------------------------------------------
# Example / demo usage
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    from pipeline.correlation import correlate_artifacts

    # ---- Mock data ----
    pslist_df = pd.DataFrame({
        "PID":           [1000, 1234, 2780, 3010, 4444, 5678],
        "PPID":          [500,  4444, 1384, 1384, 1384, 4444],
        "ImageFileName": [
            "explorer.exe", "powershell.exe", "BitTorrent.exe",
            "AnyDesk.exe", "winword.exe", "cmd.exe",
        ],
    })
    netscan_df = pd.DataFrame({
        "PID":         [2780, 2780, 3010, 1234],
        "Proto":       ["TCPv4"] * 4,
        "LocalAddr":   ["192.168.1.10"] * 4,
        "ForeignAddr": ["198.51.100.1", "0.0.0.0", "203.0.113.50", "10.0.0.5"],
        "State":       ["ESTABLISHED", "LISTENING", "ESTABLISHED", "ESTABLISHED"],
    })
    malfind_df = pd.DataFrame({
        "PID":        [1234, 5678],
        "Process":    ["powershell.exe", "cmd.exe"],
        "Protection": ["PAGE_EXECUTE_READWRITE"] * 2,
    })

    # ---- Correlate → Enrich → Alert ----
    correlated = correlate_artifacts(pslist_df, netscan_df, malfind_df)
    enriched = enrich_with_explanations(correlated)
    alerts = generate_alerts(enriched)

    print("=" * 72)
    print("ENRICHED DATA")
    print("=" * 72)
    print(enriched[["PID", "ImageFileName", "severity",
                     "correlation_score", "explanation"]].to_string(index=False))
    print()

    print("=" * 72)
    print("ALERTS (HIGH + MEDIUM only)")
    print("=" * 72)
    print(alerts.to_string(index=False))
    print()

    print("=" * 72)
    print("INVESTIGATION SUMMARY")
    print("=" * 72)
    print(explain_summary(enriched))
