import logging
import json
from typing import Dict, Any
from core.rules.engine import DetectionEngine
from case_management.manager import CaseManager
# Fallback admin context user ID (usually 1 due to core/security.py startup behavior)
SYSTEM_ADMIN_USER_ID = 1

logger = logging.getLogger(__name__)

class IngestionService:
    def __init__(self, rule_engine: DetectionEngine, case_manager: CaseManager):
        self.rule_engine = rule_engine
        self.case_manager = case_manager

    def process_event(self, event_type: str, data: Dict[str, Any], source: str) -> Dict[str, Any]:
        """
        Takes raw event, normalizes it, evaluates against active Detection-as-Code rules,
        and manages case assignment / alert streams.
        """
        # 1. Normalization (Flatten event mapping to feed cleanly into rule engine)
        event_obj = {"type": event_type, "source": source, **data}

        # 2. Rule Evaluation
        rules = self.case_manager.get_rules(active_only=True)
        # We need rules formatted explicitly for the engine. They are stored as JSON strings in the DB.
        formatted_rules = []
        for r in rules:
            try:
                r["conditions"] = json.loads(r["conditions_json"])
                formatted_rules.append(r)
            except Exception as e:
                logger.error(f"Rule {r['id']} has invalid JSON logic block.")

        matched_rules = self.rule_engine.evaluate_all(formatted_rules, event_obj)
        
        if not matched_rules:
            return {"status": "processed", "matches": 0, "case_id": None}

        # 3. Handle Auto-Case Generation
        # Get highest severity from matches
        severities = [r.get("severity", "LOW").upper() for r in matched_rules]
        if "CRITICAL" in severities:
            top_sev = "CRITICAL"
        elif "HIGH" in severities:
            top_sev = "HIGH"
        elif "MEDIUM" in severities:
            top_sev = "MEDIUM"
        else:
            top_sev = "LOW"

        # Create or find a Sliding Window Case
        case_id = self.case_manager.find_or_create_case_for_host(source, SYSTEM_ADMIN_USER_ID, time_threshold_hours=24)

        # 4. Integrate back to Pipeline 
        for match in matched_rules:
            self.case_manager.append_alert_stream(
                case_id=case_id,
                rule_id=match["id"],
                event_data=event_obj,
                severity=match.get("severity", "LOW")
            )
            
            # Formally append to the Case State to trigger analytical engine awareness
            # Fetch existing state and append to pseudo-timeline specifically called stream_events
            case = self.case_manager.get_case(case_id)
            state = case.get("session_state", {}) if isinstance(case.get("session_state"), dict) else {}
            stream = state.get("stream_events", [])
            stream.append({"rule": match["name"], "event": event_obj})
            state["stream_events"] = stream
            
            self.case_manager.update_state(case_id, session_state=state)

        return {
            "status": "alert",
            "matches": len(matched_rules),
            "severity": top_sev,
            "case_id": case_id,
            "matched_rules": [m["name"] for m in matched_rules]
        }
