import pandas as pd
import re
from typing import Dict, List, Tuple, Any

def extract_network_nodes(timeline_df: pd.DataFrame) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Extract network nodes and connections from the timeline."""
    nodes = {}
    edges = set()
    
    if timeline_df is None or timeline_df.empty or 'event_type' not in timeline_df.columns:
        return [], []
        
    net_events = timeline_df[timeline_df['event_type'] == 'network_connect']
    
    # Description format: "process_name (PID 1234) connected to 1.2.3.4:80 (ESTABLISHED, TCPv4)."
    ip_port_pattern = re.compile(r'connected to\s+([a-fA-F0-9\.:]+)')
    
    for _, row in net_events.iterrows():
        desc = str(row.get('description', ''))
        match = ip_port_pattern.search(desc)
        if match:
            ip_port = match.group(1).split()[0]  # Take the first token
            ip_port = ip_port.split('(')[0].strip()  # Clean up any trailing parentheses
            
            node_id = f"ip_{ip_port}"
            nodes[node_id] = {
                "id": node_id,
                "label": ip_port,
                "type": "network"
            }
            
            pid = str(row.get('pid', ''))
            if pid and pid != '?':
                source_id = f"pid_{pid}"
                edge_tuple = (source_id, node_id, "network_connection")
                edges.add(edge_tuple)
                
    edges_list = [{"source": s, "target": t, "type": ty} for s, t, ty in edges]
    return list(nodes.values()), edges_list

def build_process_nodes(correlation_df: pd.DataFrame) -> List[Dict[str, Any]]:
    """Build process nodes from the correlation dataframe."""
    nodes = {}
    
    if correlation_df is None or correlation_df.empty or 'PID' not in correlation_df.columns:
        return []
        
    for _, row in correlation_df.iterrows():
        pid = str(row['PID'])
        node_id = f"pid_{pid}"
        
        # Defensive coding for potential column variations
        label = str(row.get('ImageFileName', row.get('Process Name', row.get('process_name', 'unknown'))))
        severity = str(row.get('severity', 'LOW'))
        correlation_score = int(row.get('correlation_score', 0))
        
        nodes[node_id] = {
            "id": node_id,
            "label": label,
            "type": "process",
            "severity": severity,
            "correlation_score": correlation_score
        }
        
    return list(nodes.values())

def build_injection_nodes(timeline_df: pd.DataFrame) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Extract injection marker nodes and their edges."""
    nodes = {}
    edges = set()
    
    if timeline_df is None or timeline_df.empty or 'event_type' not in timeline_df.columns:
        return [], []
        
    inj_events = timeline_df[timeline_df['event_type'] == 'injection']
    for _, row in inj_events.iterrows():
        pid = str(row.get('pid', ''))
        if pid and pid != '?':
            node_id = f"inject_{pid}"
            nodes[node_id] = {
                "id": node_id,
                "label": "Memory Injection",
                "type": "injection"
            }
            
            source_id = f"pid_{pid}"
            edge_tuple = (source_id, node_id, "injection")
            edges.add(edge_tuple)
            
    edges_list = [{"source": s, "target": t, "type": ty} for s, t, ty in edges]
    return list(nodes.values()), edges_list

def build_parent_child_edges(correlation_df: pd.DataFrame) -> List[Dict[str, Any]]:
    """Extract process hierarchy edges from correlation dataframe."""
    edges = set()
    
    if correlation_df is None or correlation_df.empty or 'PID' not in correlation_df.columns:
        return []
        
    # Build set of valid PIDs to ensure edges only point to existing nodes
    valid_pids = set(str(p) for p in correlation_df['PID'])
    
    for _, row in correlation_df.iterrows():
        pid = str(row['PID'])
        ppid_val = row.get('Parent', row.get('PPID', ''))
        
        if pd.notna(ppid_val) and ppid_val != "":
            # Convert float to int first to remove decimals if present
            try:
                ppid = str(int(float(ppid_val)))
            except ValueError:
                ppid = str(ppid_val)
                
            if ppid in valid_pids and ppid != pid:
                source_id = f"pid_{ppid}"
                target_id = f"pid_{pid}"
                edge_tuple = (source_id, target_id, "parent_child")
                edges.add(edge_tuple)
            
    return [{"source": s, "target": t, "type": ty} for s, t, ty in edges]

def build_attack_graph(correlation_df: pd.DataFrame, timeline_df: pd.DataFrame) -> dict:
    """
    Construct a JSON-serializable graph structure defining processes,
    network interactions, and memory injections.
    """
    nodes_dict = {}
    edges_set = set()
    
    # 1. Add Process Nodes
    for n in build_process_nodes(correlation_df):
        nodes_dict[n['id']] = n
        
    # 2. Add Network Nodes & Edges
    net_nodes, net_edges = extract_network_nodes(timeline_df)
    for n in net_nodes:
        nodes_dict[n['id']] = n
    for e in net_edges:
        edges_set.add((e['source'], e['target'], e['type']))
        
    # 3. Add Injection Nodes & Edges
    inj_nodes, inj_edges = build_injection_nodes(timeline_df)
    for n in inj_nodes:
        nodes_dict[n['id']] = n
    for e in inj_edges:
        edges_set.add((e['source'], e['target'], e['type']))
        
    # 4. Add Parent-Child Process Edges
    pc_edges = build_parent_child_edges(correlation_df)
    for e in pc_edges:
        edges_set.add((e['source'], e['target'], e['type']))
        
    final_nodes = list(nodes_dict.values())
    final_edges = [{"source": s, "target": t, "type": ty} for s, t, ty in edges_set]
    
    return {
        "nodes": final_nodes,
        "edges": final_edges
    }

def summarize_graph(graph: dict) -> str:
    """Generate a coherent narrative summary parsing the extracted graph data."""
    nodes = graph.get("nodes", [])
    edges = graph.get("edges", [])
    
    processes = [n for n in nodes if n["type"] == "process"]
    networks = [n for n in nodes if n["type"] == "network"]
    injections = [n for n in nodes if n["type"] == "injection"]
    
    suspicious_count = sum(1 for p in processes if p.get("severity") in ("HIGH", "MEDIUM"))
    
    net_sources = set()
    for e in edges:
        if e["type"] == "network_connection":
            source_id = e["source"]
            for p in processes:
                if p["id"] == source_id:
                    net_sources.add(p.get("label", "unknown process"))
                    break
                    
    parts = []
    parts.append(f"Graph shows {len(processes)} processes")
    if suspicious_count > 0:
         parts.append(f"{suspicious_count} suspicious nodes")
    else:
         parts.append("no highly suspicious nodes")
         
    if len(networks) > 0:
        srcs = ", ".join(net_sources) if net_sources else "unknown sources"
        parts.append(f"{len(networks)} external network connection(s) originating from {srcs}")
    
    if len(injections) > 0:
        parts.append(f"{len(injections)} memory injection indicator(s)")
        
    if len(parts) > 1:
        summary = ", ".join(parts[:-1]) + ", and " + parts[-1] + "."
    elif len(parts) == 1:
        summary = parts[0] + "."
    else:
        summary = "Graph is empty."
        
    return summary.capitalize()

if __name__ == "__main__":
    import json
    
    # Mock Correlation DataFrame
    correlation_data = {
        "PID": [1000, 2000, 3000],
        "PPID": [500, 1000, 2000],
        "ImageFileName": ["explorer.exe", "powershell.exe", "malware.exe"],
        "has_network": [False, True, False],
        "has_injection": [False, False, True],
        "correlation_score": [0, 5, 8],
        "severity": ["LOW", "MEDIUM", "HIGH"]
    }
    corr_df = pd.DataFrame(correlation_data)
    
    # Mock Timeline DataFrame
    timeline_data = {
        "timestamp": ["2026-04-10 10:00:00", "2026-04-10 10:05:00", "2026-04-10 10:10:00"],
        "event_type": ["process_start", "network_connect", "injection"],
        "pid": [2000, 2000, 3000],
        "process_name": ["powershell.exe", "powershell.exe", "malware.exe"],
        "severity": ["MEDIUM", "MEDIUM", "HIGH"],
        "description": [
            "powershell.exe (PID 2000) started.",
            "powershell.exe (PID 2000) connected to 8.8.8.8:443 (ESTABLISHED, TCPv4).",
            "Memory injection detected in malware.exe (PID 3000)."
        ]
    }
    time_df = pd.DataFrame(timeline_data)
    
    # Generate Graph
    graph_output = build_attack_graph(corr_df, time_df)
    print("--- Graph JSON ---")
    print(json.dumps(graph_output, indent=2))
    
    print("\n--- Graph Summary ---")
    print(summarize_graph(graph_output))
