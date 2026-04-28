import pandas as pd
from typing import Dict, List

class BehaviorSignatureEngine:
    def __init__(self):
        # Define some basic signatures
        # A signature returns True if it matches a specific row in the enriched DF or net/timeline
        pass

    def evaluate_signatures(self, enriched_df: pd.DataFrame) -> List[Dict[str, str]]:
        """
        Evaluate heuristic signatures against the enriched process list.
        """
        matches = []
        if enriched_df is None or enriched_df.empty:
            return matches

        for _, row in enriched_df.iterrows():
            proc_name = str(row.get('ImageFileName', '')).lower()
            pid = str(row.get('PID', ''))
            has_net = row.get('has_network', False)
            has_inj = row.get('has_injection', False)
            susp_parent = row.get('suspicious_parent', False)

            # Signature 1: LOLBin Network Activity
            lolbins = ["powershell.exe", "cmd.exe", "mshta.exe", "certutil.exe", "regsvr32.exe"]
            if proc_name in lolbins and has_net:
                matches.append({
                    "signature": "LOLBin Network Activity",
                    "pid": pid,
                    "process": proc_name,
                    "description": f"{proc_name} is a Living-Off-The-Land binary that initiated an external connection."
                })

            # Signature 2: Injected Process with Network
            if has_inj and has_net:
                matches.append({
                    "signature": "Injected Network Activity",
                    "pid": pid,
                    "process": proc_name,
                    "description": f"{proc_name} shows memory injection AND network activity, highly indicative of C2."
                })

            # Signature 3: Suspicious Parent doing Injection
            if susp_parent and has_inj:
                matches.append({
                    "signature": "Anomalous Injection Chain",
                    "pid": pid,
                    "process": proc_name,
                    "description": f"{proc_name} was spawned by an unusual parent and shows memory injection."
                })

        return matches
