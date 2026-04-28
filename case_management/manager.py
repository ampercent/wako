from .db import CaseDatabase
from typing import Dict, Any, List
import json

class CaseManager:
    def __init__(self, db_path: str = "C:/Major_Project/cases.db"):
        self.db = CaseDatabase(db_path)

    def create_case(self, data: Dict[str, Any], owner_id: int = 1) -> Dict[str, Any]:
        name = data.get("name", "Unnamed Case")
        description = data.get("description", "")
        dump_file = data.get("dump_file", "unknown.dmp")
        
        case_id = self.db.create_case(name, description, dump_file, owner_id)
        return self.get_case_summary(case_id)

    def get_case(self, case_id: int) -> Dict[str, Any]:
        case = self.db.get_case(case_id)
        if not case:
            return None
            
        # Parse JSON states
        for field in ['alerts_state', 'timeline_state', 'graph_state', 'session_state']:
            if case.get(field):
                try:
                    case[field] = json.loads(case[field])
                except Exception:
                    case[field] = None
                    
        # include notes
        case["notes"] = self.db.get_notes(case_id)
        return case

    def get_case_summary(self, case_id: int) -> Dict[str, Any]:
        case = self.db.get_case(case_id)
        if case:
            # remove large states
            case.pop('alerts_state', None)
            case.pop('timeline_state', None)
            case.pop('graph_state', None)
        return case

    def get_all_cases(self) -> List[Dict[str, Any]]:
        return self.db.get_all_cases()

    def update_state(self, case_id: int, alerts=None, timeline=None, graph=None, session_state=None):
        self.db.update_case_state(case_id, alerts, timeline, graph, session_state)
        return {"status": "success", "message": "State updated"}

    def add_note(self, case_id: int, entity_type: str, entity_id: str, note_text: str, user_id: int = 1):
        note_id = self.db.add_note(case_id, entity_type, str(entity_id), note_text, user_id)
        return {"id": note_id, "status": "added"}

    def get_notes(self, case_id: int, entity_type: str = None, entity_id: str = None):
        return self.db.get_notes(case_id, entity_type, str(entity_id) if entity_id else None)

    # Multi-User Features
    
    def register_user(self, username: str, password_hash: str, role: str = 'analyst'):
        try:
            return self.db.create_user(username, password_hash, role)
        except Exception:
            return None
            
    def get_user_by_username(self, username: str):
        return self.db.get_user_by_username(username)

    def share_case(self, case_id: int, owner_id: int, target_username: str, role: str):
        target_user = self.db.get_user_by_username(target_username)
        if not target_user:
            return {"status": "error", "message": "User not found"}
            
        case = self.db.get_case(case_id)
        if not case or case.get("owner_id") != owner_id:
            # We also allow sharing if the user is a system admin, but let's just stick to owner check for simple case
            if owner_id != 1: # Default bypass for admin
                return {"status": "error", "message": "Only owner can share"}

        self.db.share_case(case_id, target_user["id"], role)
        self.db.log_activity(case_id, owner_id, "case_shared", json.dumps({"target": target_username, "role": role}))
        return {"status": "success"}

    def add_comment(self, case_id: int, user_id: int, entity_type: str, entity_id: str, comment: str):
        comment_id = self.db.add_comment(case_id, user_id, entity_type, str(entity_id), comment)
        self.db.log_activity(case_id, user_id, "comment_added", json.dumps({"entity_type": entity_type, "entity_id": entity_id}))
        return {"id": comment_id, "status": "added"}

    def get_comments(self, case_id: int, entity_type: str = None, entity_id: str = None):
        return self.db.get_comments(case_id, entity_type, str(entity_id) if entity_id else None)

    def log_activity(self, case_id: int, user_id: int, action: str, details: Dict[str, Any]):
        self.db.log_activity(case_id, user_id, action, json.dumps(details))

    def get_activity_log(self, case_id: int):
        return self.db.get_activity_log(case_id)

    def log_action(self, case_id: int, user_id: int, action_name: str, target: str, result: str, status: str):
        self.db.log_action(case_id, user_id, action_name, target, result, status)

    def get_action_logs(self, case_id: int):
        return self.db.get_action_logs(case_id)

    # --- Continuous Monitoring Tracking ---

    def create_rule(self, name: str, severity: str, action: str, conditions: list) -> int:
        return self.db.create_rule(name, severity, action, json.dumps(conditions))

    def get_rules(self, active_only: bool = True):
        return self.db.get_rules(active_only)

    def delete_rule(self, rule_id: int):
        self.db.delete_rule(rule_id)

    def append_alert_stream(self, case_id: int, rule_id: int, event_data: dict, severity: str):
        self.db.append_alert_stream(case_id, rule_id, json.dumps(event_data), severity)

    def get_alert_stream(self, limit: int = 50):
        return self.db.get_alert_stream(limit)

    def find_or_create_case_for_host(self, host: str, user_id: int, time_threshold_hours: int = 24) -> int:
        """Finds a recent active case for a host or creates a new one."""
        cases = self.get_all_cases()
        # Search for case dynamically created for this host
        expected_name = f"Auto-Case: {host}"
        
        # Simple threshold check - assumes cases ordered by recent (which get_cases usually does)
        import datetime
        for c in cases:
            if c.get("name") == expected_name:
                # check time
                created = datetime.datetime.fromisoformat(c["created_at"])
                if (datetime.datetime.now() - created).total_seconds() < (time_threshold_hours * 3600):
                    return c["id"]
                    
        # If no recent case found, create one
        details = {"source": "Continuous Monitoring", "host": host}
        new_case = self.create_case({"name": expected_name, "description": f"Auto-generated case for detections on {host}"}, owner_id=user_id)
        return new_case["id"]

    # --- Hunting Engine ---
    def save_query(self, user_id: int, name: str, query: str) -> int:
        return self.db.save_query(user_id, name, query)

    def get_saved_queries(self, user_id: int):
        return self.db.get_saved_queries(user_id)

    def delete_query(self, query_id: int, user_id: int):
        self.db.delete_query(query_id, user_id)
