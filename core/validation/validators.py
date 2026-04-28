"""
Data Validation Layer — Schema and sanity checks.
====================================================
Ensures integrity of all processed forensic data with clear,
actionable error messages. Validates DataFrames before they
enter the correlation pipeline.
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional, Set

import pandas as pd

logger = logging.getLogger(__name__)


@dataclass
class ValidationResult:
    """
    Outcome of a validation check.

    Attributes
    ----------
    valid : bool
        ``True`` if no hard errors were found.
    errors : list[str]
        Critical issues that should prevent processing.
    warnings : list[str]
        Non-critical issues logged for awareness.
    """
    valid: bool = True
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


class DataValidator:
    """
    Validates forensic DataFrames for schema compliance and data sanity.

    All methods are stateless and can be called independently.
    """

    # ------------------------------------------------------------------
    # Schema validators
    # ------------------------------------------------------------------

    def validate_pslist(self, df: pd.DataFrame) -> ValidationResult:
        """
        Validate the process list DataFrame.

        Required columns: ``PID``, ``PPID``, ``ImageFileName``.
        PID and PPID must be numeric.

        Parameters
        ----------
        df : pd.DataFrame
            Process list from Volatility ``windows.pslist``.

        Returns
        -------
        ValidationResult
        """
        result = ValidationResult()

        if df is None or df.empty:
            result.warnings.append("pslist DataFrame is empty or None.")
            return result

        # Required columns
        required = {"PID", "PPID", "ImageFileName"}
        missing = required - set(df.columns)
        if missing:
            result.valid = False
            result.errors.append(f"pslist missing required columns: {missing}")
            return result

        # Type checks
        for col in ("PID", "PPID"):
            try:
                pd.to_numeric(df[col], errors="raise")
            except (ValueError, TypeError):
                result.warnings.append(
                    f"pslist column '{col}' contains non-numeric values. "
                    f"Sample: {df[col].head(3).tolist()}"
                )

        # ImageFileName should be non-empty strings
        empty_names = df["ImageFileName"].isna() | (df["ImageFileName"].astype(str).str.strip() == "")
        if empty_names.any():
            count = int(empty_names.sum())
            result.warnings.append(f"pslist has {count} row(s) with empty ImageFileName.")

        return result

    def validate_netscan(self, df: pd.DataFrame) -> ValidationResult:
        """
        Validate the network scan DataFrame.

        Expected columns: ``PID``. Optional: ``ForeignAddr``, ``State``.

        Parameters
        ----------
        df : pd.DataFrame
            Network scan from Volatility ``windows.netscan``.

        Returns
        -------
        ValidationResult
        """
        result = ValidationResult()

        if df is None or df.empty:
            result.warnings.append("netscan DataFrame is empty or None.")
            return result

        if "PID" not in df.columns:
            result.valid = False
            result.errors.append("netscan missing required column: PID")
            return result

        # PID type check
        try:
            pd.to_numeric(df["PID"], errors="raise")
        except (ValueError, TypeError):
            result.warnings.append("netscan 'PID' column contains non-numeric values.")

        # ForeignAddr sanity
        if "ForeignAddr" in df.columns:
            empty_addrs = df["ForeignAddr"].isna() | (df["ForeignAddr"].astype(str).str.strip() == "")
            if empty_addrs.any():
                result.warnings.append(
                    f"netscan has {int(empty_addrs.sum())} row(s) with empty ForeignAddr."
                )

        return result

    def validate_malfind(self, df: pd.DataFrame) -> ValidationResult:
        """
        Validate the malfind DataFrame.

        Expected columns: ``PID``. Optional: ``Process``, ``Protection``.

        Parameters
        ----------
        df : pd.DataFrame
            Memory injection data from ``windows.malfind``.

        Returns
        -------
        ValidationResult
        """
        result = ValidationResult()

        if df is None or df.empty:
            result.warnings.append("malfind DataFrame is empty or None.")
            return result

        if "PID" not in df.columns:
            result.valid = False
            result.errors.append("malfind missing required column: PID")
            return result

        return result

    # ------------------------------------------------------------------
    # Sanity validators
    # ------------------------------------------------------------------

    def check_pid_consistency(
        self,
        pslist_df: pd.DataFrame,
        netscan_df: pd.DataFrame,
    ) -> List[str]:
        """
        Check that PIDs referenced in netscan exist in pslist.

        Parameters
        ----------
        pslist_df : pd.DataFrame
            Process list.
        netscan_df : pd.DataFrame
            Network scan.

        Returns
        -------
        list[str]
            Warning messages for orphaned PIDs.
        """
        warnings: List[str] = []

        if pslist_df is None or pslist_df.empty or "PID" not in pslist_df.columns:
            return warnings
        if netscan_df is None or netscan_df.empty or "PID" not in netscan_df.columns:
            return warnings

        ps_pids: Set[int] = set(pd.to_numeric(pslist_df["PID"], errors="coerce").dropna().astype(int))
        net_pids: Set[int] = set(pd.to_numeric(netscan_df["PID"], errors="coerce").dropna().astype(int))

        orphans = net_pids - ps_pids
        if orphans:
            warnings.append(
                f"PID consistency: {len(orphans)} network PID(s) not found in pslist: "
                f"{sorted(orphans)[:10]}"
            )

        return warnings

    def check_timestamp_validity(
        self,
        df: pd.DataFrame,
        ts_col: str = "CreateTime",
    ) -> List[str]:
        """
        Flag invalid timestamps in a DataFrame column.

        Checks for:
        - Dates before year 2000 (likely parse errors)
        - Dates in the far future (>2030)
        - Completely unparseable values

        Parameters
        ----------
        df : pd.DataFrame
            DataFrame to check.
        ts_col : str
            Column name containing timestamps.

        Returns
        -------
        list[str]
            Warning messages.
        """
        warnings: List[str] = []

        if df is None or df.empty or ts_col not in df.columns:
            return warnings

        timestamps = pd.to_datetime(df[ts_col], errors="coerce")

        # Count NaT (unparseable)
        nat_count = int(timestamps.isna().sum())
        original_non_null = int(df[ts_col].notna().sum())
        if nat_count > 0 and original_non_null > 0:
            warnings.append(
                f"Timestamp validation: {nat_count} unparseable timestamp(s) in '{ts_col}'."
            )

        # Date range checks on valid timestamps
        valid = timestamps.dropna()
        if not valid.empty:
            # Convert to tz-naive for comparison
            if valid.dt.tz is not None:
                valid = valid.dt.tz_localize(None)

            too_old = (valid < pd.Timestamp("2000-01-01")).sum()
            too_new = (valid > pd.Timestamp("2030-12-31")).sum()

            if too_old > 0:
                warnings.append(
                    f"Timestamp validation: {int(too_old)} timestamp(s) before year 2000 in '{ts_col}'."
                )
            if too_new > 0:
                warnings.append(
                    f"Timestamp validation: {int(too_new)} timestamp(s) after year 2030 in '{ts_col}'."
                )

        return warnings

    def check_duplicate_pids(self, df: pd.DataFrame) -> List[str]:
        """
        Warn about duplicate PID entries in a process list.

        Parameters
        ----------
        df : pd.DataFrame
            Process list DataFrame.

        Returns
        -------
        list[str]
            Warning messages.
        """
        warnings: List[str] = []

        if df is None or df.empty or "PID" not in df.columns:
            return warnings

        dups = df["PID"].duplicated(keep=False)
        if dups.any():
            dup_pids = sorted(df.loc[dups, "PID"].unique().tolist())[:10]
            warnings.append(
                f"Duplicate PIDs detected: {dup_pids}"
            )

        return warnings
