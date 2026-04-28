import pandas as pd
from typing import Dict, Any, List

def build_process_tree(pslist_df: pd.DataFrame, enriched_df: pd.DataFrame = None) -> List[Dict[str, Any]]:
    """
    Builds a hierarchical Process Tree from the flat pslist dataframe.
    """
    if pslist_df is None or pslist_df.empty or 'PID' not in pslist_df.columns or 'PPID' not in pslist_df.columns:
        return []

    # Create enrichment lookup
    enrichment_map = {}
    if enriched_df is not None and not enriched_df.empty and 'PID' in enriched_df.columns:
        for _, row in enriched_df.iterrows():
            pid = int(row['PID'])
            enrichment_map[pid] = {
                "severity": row.get('severity', 'LOW'),
                "score": row.get('correlation_score', 0),
                "is_suspicious": row.get('severity') in ['HIGH', 'MEDIUM']
            }

    # First pass: Create node dicts
    nodes = {}
    for _, row in pslist_df.iterrows():
        try:
            pid = int(row['PID'])
            ppid = int(row['PPID'])
        except (ValueError, TypeError):
            continue
            
        nodes[pid] = {
            "id": str(pid),
            "pid": pid,
            "ppid": ppid,
            "name": str(row.get('ImageFileName', 'unknown')),
            "children": [],
            "threat_info": enrichment_map.get(pid, {"severity": "LOW", "score": 0, "is_suspicious": False})
        }

    # Second pass: Build hierarchy
    tree = []
    for pid, node in nodes.items():
        ppid = node['ppid']
        # If parent exists in our nodes, attach as child
        if ppid in nodes and ppid != pid:
            nodes[ppid]["children"].append(node)
        else:
            # If parent doesn't exist (e.g. system idle process or exited process), it's a root
            tree.append(node)
            
    # Third pass: Bubble up suspicion flags visually
    def bubble_suspicion(node):
        has_suspicious_child = False
        for child in node["children"]:
            if bubble_suspicion(child):
                has_suspicious_child = True
        
        node["has_suspicious_descendant"] = has_suspicious_child
        return has_suspicious_child or node["threat_info"]["is_suspicious"]

    for root in tree:
        bubble_suspicion(root)

    return tree
