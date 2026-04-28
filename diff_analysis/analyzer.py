import pandas as pd
from typing import Dict, List, Any, Optional

import logging

logger = logging.getLogger(__name__)


class DiffAnalyzer:
    """
    Cross-dump forensic comparison engine.

    Supports single-pair and multi-dump investigation, including
    timeline merging, correlation comparison, and process/connection diffs.
    """

    def compare_dumps(self, base_pslist: pd.DataFrame, target_pslist: pd.DataFrame, 
                      base_netscan: pd.DataFrame, target_netscan: pd.DataFrame) -> Dict[str, Any]:
        """
        Compares a baseline and target to find newly spawned processes and new connections.
        """
        results = {
            "new_processes": [],
            "missing_processes": [],
            "new_connections": []
        }

        # 1. Process Diffs
        if base_pslist is not None and not base_pslist.empty and target_pslist is not None and not target_pslist.empty:
            if 'ImageFileName' in base_pslist.columns and 'ImageFileName' in target_pslist.columns:
                base_names = set(base_pslist['ImageFileName'].dropna().unique())
                target_names = set(target_pslist['ImageFileName'].dropna().unique())
                
                results["new_processes"] = list(target_names - base_names)
                results["missing_processes"] = list(base_names - target_names)

        # 2. Connection Diffs
        if base_netscan is not None and not base_netscan.empty and target_netscan is not None and not target_netscan.empty:
            if 'ForeignAddr' in base_netscan.columns and 'ForeignAddr' in target_netscan.columns:
                base_ips = set(base_netscan['ForeignAddr'].dropna().unique())
                target_ips = set(target_netscan['ForeignAddr'].dropna().unique())
                
                # Cleanup typical non-external IPs
                clean = lambda ips: {ip for ip in ips if ip not in ("0.0.0.0", "*", "::", "127.0.0.1", "")}
                
                new_ips = clean(target_ips) - clean(base_ips)
                
                for ip in new_ips:
                    # Find which process initiated it in target
                    procs = target_netscan[target_netscan['ForeignAddr'] == ip]['Owner'].dropna().unique()
                    proc_str = ", ".join([str(p) for p in procs]) if len(procs) > 0 else "Unknown"
                    results["new_connections"].append({
                        "ip": ip,
                        "process": proc_str
                    })

        return results

    # ------------------------------------------------------------------
    # Multi-dump analysis methods
    # ------------------------------------------------------------------

    def merge_timelines(
        self,
        timeline_a: pd.DataFrame,
        timeline_b: pd.DataFrame,
        label_a: str = "dump_A",
        label_b: str = "dump_B",
    ) -> pd.DataFrame:
        """
        Merge two forensic timelines into a unified chronological view.

        Each event is tagged with a ``source`` label to identify its origin dump.

        Parameters
        ----------
        timeline_a : pd.DataFrame
            Timeline from the first (baseline) dump.
        timeline_b : pd.DataFrame
            Timeline from the second (target) dump.
        label_a : str
            Source label for baseline events.
        label_b : str
            Source label for target events.

        Returns
        -------
        pd.DataFrame
            Merged timeline sorted by timestamp, with a ``source`` column.
        """
        frames: List[pd.DataFrame] = []

        if timeline_a is not None and not timeline_a.empty:
            ta = timeline_a.copy()
            ta["source"] = label_a
            frames.append(ta)

        if timeline_b is not None and not timeline_b.empty:
            tb = timeline_b.copy()
            tb["source"] = label_b
            frames.append(tb)

        if not frames:
            return pd.DataFrame()

        merged = pd.concat(frames, ignore_index=True)

        # Sort chronologically
        if "timestamp" in merged.columns:
            merged["timestamp"] = pd.to_datetime(merged["timestamp"], errors="coerce")
            merged = merged.sort_values("timestamp", ascending=True, na_position="last")

        return merged.reset_index(drop=True)

    def compare_correlations(
        self,
        corr_a: pd.DataFrame,
        corr_b: pd.DataFrame,
    ) -> Dict[str, Any]:
        """
        Compare correlation outputs from two dumps.

        Detects:
        - New processes (by name) in the target
        - Missing processes from the baseline
        - Score changes for processes present in both
        - New behavioral flags (injection, network, suspicious parent)

        Parameters
        ----------
        corr_a : pd.DataFrame
            Correlation output from the baseline dump.
        corr_b : pd.DataFrame
            Correlation output from the target dump.

        Returns
        -------
        dict
            Structured diff with keys: ``new_processes``, ``missing_processes``,
            ``score_changes``, ``new_flags``.
        """
        result: Dict[str, Any] = {
            "new_processes": [],
            "missing_processes": [],
            "score_changes": [],
            "new_flags": [],
        }

        if corr_a is None or corr_a.empty or corr_b is None or corr_b.empty:
            return result

        if "ImageFileName" not in corr_a.columns or "ImageFileName" not in corr_b.columns:
            return result

        # Build name → row lookups
        base_by_name: Dict[str, pd.Series] = {}
        for _, row in corr_a.iterrows():
            name = str(row["ImageFileName"]).lower()
            if name not in base_by_name:
                base_by_name[name] = row

        target_by_name: Dict[str, pd.Series] = {}
        for _, row in corr_b.iterrows():
            name = str(row["ImageFileName"]).lower()
            if name not in target_by_name:
                target_by_name[name] = row

        base_names = set(base_by_name.keys())
        target_names = set(target_by_name.keys())

        # New / missing processes
        for name in sorted(target_names - base_names):
            row = target_by_name[name]
            result["new_processes"].append({
                "process": str(row.get("ImageFileName", name)),
                "pid": int(row.get("PID", 0)),
                "correlation_score": int(row.get("correlation_score", 0)),
            })

        for name in sorted(base_names - target_names):
            row = base_by_name[name]
            result["missing_processes"].append({
                "process": str(row.get("ImageFileName", name)),
                "pid": int(row.get("PID", 0)),
            })

        # Score changes and new flags for common processes
        common = base_names & target_names
        flag_cols = ["has_network", "has_injection", "suspicious_parent"]

        for name in sorted(common):
            base_row = base_by_name[name]
            target_row = target_by_name[name]

            base_score = int(base_row.get("correlation_score", 0))
            target_score = int(target_row.get("correlation_score", 0))

            if base_score != target_score:
                result["score_changes"].append({
                    "process": str(target_row.get("ImageFileName", name)),
                    "pid": int(target_row.get("PID", 0)),
                    "base_score": base_score,
                    "target_score": target_score,
                    "delta": target_score - base_score,
                })

            # Check for newly set flags
            for flag in flag_cols:
                base_val = bool(base_row.get(flag, False))
                target_val = bool(target_row.get(flag, False))
                if not base_val and target_val:
                    result["new_flags"].append({
                        "process": str(target_row.get("ImageFileName", name)),
                        "pid": int(target_row.get("PID", 0)),
                        "flag": flag,
                    })

        return result
