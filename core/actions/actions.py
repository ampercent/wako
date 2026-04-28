import os
from typing import Dict, Any
from core.actions.engine import Action
from case_management.manager import CaseManager
from reporting.engine import ReportGenerator

class BlockIPAction(Action):
    name = "block_ip"
    description = "Blocks an IP address (simulated by default)."

    def execute(self, context: Dict[str, Any]) -> Dict[str, Any]:
        target_ip = context.get("target")
        if not target_ip:
            return {"status": "error", "message": "Missing 'target' IP address"}
            
        simulate = context.get("simulate_mode", True)
        if simulate:
            msg = f"[SIMULATION] Blocked IP {target_ip} at network boundary."
        else:
            # Placeholder for actual blocklogic e.g., fwsam
            msg = f"Successfully blocked IP {target_ip} in firewall."
            
        return {"status": "success", "message": msg, "target": target_ip}

class TerminateProcessAction(Action):
    name = "terminate_process"
    description = "Sends a termination signal to a specified PID."

    def execute(self, context: Dict[str, Any]) -> Dict[str, Any]:
        pid = context.get("target")
        if not pid:
            return {"status": "error", "message": "Missing 'target' PID"}
            
        simulate = context.get("simulate_mode", True)
        if simulate:
            msg = f"[SIMULATION] Terminated PID {pid}."
        else:
            msg = f"Killed PID {pid} via EDR integration."
            
        return {"status": "success", "message": msg, "target": pid}

class ExportEvidenceAction(Action):
    name = "export_evidence"
    description = "Exports the case as a forensic JSON evidence package."

    def execute(self, context: Dict[str, Any]) -> Dict[str, Any]:
        case_id = context.get("case_id")
        manager: CaseManager = context.get("manager")
        
        if not case_id or not manager:
            return {"status": "error", "message": "Missing case_id or manager context"}
            
        try:
            case_data = manager.get_case(case_id)
            if not case_data:
                 return {"status": "error", "message": "Case not found."}

            rg = ReportGenerator()
            # the action exports JSON report. 
            alerts = case_data.get("alerts_state", [])
            timeline = case_data.get("timeline_state", [])
            
            report_path = rg.generate_json_report(case_id, case_data, alerts, timeline)
            return {"status": "success", "message": f"Evidence exported successfully to {report_path}", "file_path": report_path}
        except Exception as e:
            return {"status": "error", "message": f"Export failed: {str(e)}"}

class TagMaliciousAction(Action):
    name = "tag_malicious"
    description = "Tags an entity as definitively malicious."

    def execute(self, context: Dict[str, Any]) -> Dict[str, Any]:
        target = context.get("target") # e.g., '10.0.0.1' or 'PID 1234'
        case_id = context.get("case_id")
        manager: CaseManager = context.get("manager")
        user_id = context.get("user_id")

        if not all([target, case_id, manager, user_id]):
            return {"status": "error", "message": "Missing target, case_id, user_id or manager context"}
            
        manager.add_note(
            case_id=case_id,
            entity_type="target",
            entity_id=str(target),
            note_text="[ACTION] Formally tagged as MALICIOUS by analyst.",
            user_id=user_id
        )
        
        return {"status": "success", "message": f"Tagged {target} as malicious in case notes."}
