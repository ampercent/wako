from typing import List, Dict, Any

class PlaybookEngine:
    def __init__(self):
        self.playbooks = {
            "memory_injection": {
                "name": "Memory Injection Investigation",
                "trigger": "malfind hits or high risk score with injection flag",
                "steps": [
                    {"step": 1, "action": "Identify the injected process and its parent.", "tool": "Process Tree"},
                    {"step": 2, "action": "Check for external connections made by the injected PID.", "tool": "Graph / Network Tab"},
                    {"step": 3, "action": "Dump the process executable code for analysis.", "tool": "volatility windows.dumpfiles"},
                    {"step": 4, "action": "Scan the dumped regions with YARA.", "tool": "Custom YARA Engine"}
                ]
            },
            "lolbin_abuse": {
                "name": "Living-Off-The-Land (LOLBin) Abuse",
                "trigger": "powershell.exe / cmd.exe with network connections",
                "steps": [
                    {"step": 1, "action": "Identify argument history if available (e.g. via cmdline plugin).", "tool": "volatility windows.cmdline"},
                    {"step": 2, "action": "Determine if the connection was inbound or outbound.", "tool": "Network Tab"},
                    {"step": 3, "action": "Check Reputation of the foreign IP.", "tool": "Threat Intel Tooltips"},
                    {"step": 4, "action": "Determine the child processes spawned by this LOLBin to see payload execution.", "tool": "Process Tree"}
                ]
            },
             "generic_anomaly": {
                "name": "Statistical Anomaly Investigation",
                "trigger": "Process flagged by Anomaly Detection model",
                "steps": [
                    {"step": 1, "action": "Examine why the ML model flagged it (threads vs handles).", "tool": "Anomaly Tab"},
                    {"step": 2, "action": "Verify if the binary is signed or located in a standard Windows path.", "tool": "dlllist / filescan"},
                    {"step": 3, "action": "Correlate with time bursts to see if it occurred during an active phase.", "tool": "Timeline"}
                ]
            }
        }

    def get_playbook(self, playbook_id: str) -> Dict[str, Any]:
        return self.playbooks.get(playbook_id, None)

    def suggest_playbooks(self, iocs: Dict[str, Any], anomalies: List[Dict[str, Any]], signatures: List[Dict[str, str]]) -> List[Dict[str, Any]]:
        """
        Suggests playbooks to run based on current case evidence.
        """
        suggestions = []
        
        # 1. Injection
        if "Memory Injection (RWX)" in iocs.get("techniques", []):
            suggestions.append(self.playbooks["memory_injection"])
            
        # 2. LOLBin
        lolbin_sigs = [s for s in signatures if "LOLBin" in s.get("signature", "")]
        if lolbin_sigs:
            suggestions.append(self.playbooks["lolbin_abuse"])
            
        # 3. Anomaly
        if anomalies and len(anomalies) > 0:
            suggestions.append(self.playbooks["generic_anomaly"])
            
        return suggestions
