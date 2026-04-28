import pandas as pd
from typing import List, Dict, Any

def recommend_actions(correlation_df: pd.DataFrame, timeline_df: pd.DataFrame, graph_json: Dict[str, Any] = None) -> List[Dict[str, Any]]:
    """
    Scans the existing case artifacts and recommends actions mapping to the Action Engine.
    Rules:
    - HIGH severity + external network connection -> Block IP
    - Memory Injection flag -> Dump/Terminate process
    - Suspicious parent -> Terminate process
    """
    recommendations = []
    
    if correlation_df is None or correlation_df.empty:
        return recommendations
        
    # Standardize column checking
    has_sev = 'severity' in correlation_df.columns or 'Severity' in correlation_df.columns
    has_injection = 'has_injection' in correlation_df.columns or 'Memory Injection' in correlation_df.columns
    has_network = 'has_network' in correlation_df.columns or 'Network Activity' in correlation_df.columns

    sev_col = 'Severity' if 'Severity' in correlation_df.columns else ('severity' if 'severity' in correlation_df.columns else None)
    name_col = 'Process Name' if 'Process Name' in correlation_df.columns else 'ImageFileName'

    for _, row in correlation_df.iterrows():
        # Only evaluate actual High risk, avoiding NaN
        if sev_col and pd.notna(row.get(sev_col)) and str(row.get(sev_col)).upper() == 'HIGH':
            pid = row.get("PID")
            pname = row.get(name_col, "Unknown")
            
            inj_val = row.get('has_injection') or row.get('Memory Injection')
            net_val = row.get('has_network') or row.get('Network Activity')
            
            if inj_val == True or inj_val == "Yes":
                recommendations.append({
                    "action": "terminate_process",
                    "target": str(pid),
                    "reason": f"High severity process {pname} exhibiting memory injection patterns."
                })
                
            if net_val == True or net_val == "Yes":
                # In a real scenario we'd pull the exact IP from netscan here
                # Let's recommend tagging it or pulling more data
                recommendations.append({
                    "action": "tag_malicious",
                    "target": f"PID {pid}",
                    "reason": f"High severity process {pname} communicating over network."
                })

    # Timeline scanning for explicitly malicious IPs
    if timeline_df is not None and not timeline_df.empty and 'description' in timeline_df.columns:
        for text in timeline_df['description'].dropna():
            text_lower = str(text).lower()
            if ("malicious" in text_lower and "ip" in text_lower) or "external ip" in text_lower:
                # Pseudo extraction
                import re
                ips = re.findall(r'[0-9]+(?:\.[0-9]+){3}', str(text))
                for ip in ips:
                    if not ip.startswith("192.168") and not ip.startswith("10.") and not ip.startswith("127."):
                        recommendations.append({
                            "action": "block_ip",
                            "target": ip,
                            "reason": f"Observed communication to external/flagged IP {ip}."
                        })

    # Return uniquely identified recommendations
    unique_recs = {f"{r['action']}_{r['target']}": r for r in recommendations}.values()
    return list(unique_recs)
