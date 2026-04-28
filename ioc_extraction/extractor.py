import pandas as pd
import re
from typing import Dict, List, Any

class IOCExtractor:
    def __init__(self):
        # We can expand these as needed
        pass

    def extract_from_df(self, enriched_df: pd.DataFrame, netscan_df: pd.DataFrame, malfind_df: pd.DataFrame) -> Dict[str, List[str]]:
        iocs = {
            "ips": set(),
            "domains": set(), 
            "processes": set(),
            "techniques": set()
        }

        # 1. IPs from Netscan
        if netscan_df is not None and not netscan_df.empty and 'ForeignAddr' in netscan_df.columns:
            for ip in netscan_df['ForeignAddr'].dropna():
                ip_str = str(ip).strip()
                # Basic filter to ignore 0.0.0.0, 127.0.0.1, ::
                if ip_str not in ("0.0.0.0", "*", "::", "127.0.0.1", "") and not ip_str.startswith("192.168.") and not ip_str.startswith("10."):
                    iocs["ips"].add(ip_str)

        # 2. Suspicious Processes from Enriched DF
        if enriched_df is not None and not enriched_df.empty:
            if 'severity' in enriched_df.columns:
                high_risk = enriched_df[enriched_df['severity'].isin(["HIGH", "MEDIUM"])]
                if 'ImageFileName' in high_risk.columns:
                    for proc in high_risk['ImageFileName'].dropna().unique():
                        iocs["processes"].add(str(proc).strip())

        # 3. Techniques from Malfind and Enriched
        if malfind_df is not None and not malfind_df.empty:
            if 'Protection' in malfind_df.columns:
                 # If malfind hit, it's injection
                 if len(malfind_df) > 0:
                     iocs["techniques"].add("Memory Injection (RWX)")

        if enriched_df is not None and not enriched_df.empty:
            if 'suspicious_parent' in enriched_df.columns and enriched_df['suspicious_parent'].any():
                iocs["techniques"].add("Suspicious Parent-Child Hierarchy")

        # Convert sets to lists
        return {k: sorted(list(v)) for k, v in iocs.items()}
