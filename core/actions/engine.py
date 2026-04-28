import logging
import json
from datetime import datetime
from typing import Dict, Any, List, Optional
from case_management.manager import CaseManager

logger = logging.getLogger(__name__)

class Action:
    name: str = "base_action"
    description: str = "Base Action Interface"

    def execute(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute the action.
        Must return a dict containing at minimum: {"status": "success|error", "message": str}
        """
        raise NotImplementedError("Actions must implement execute()")

class ActionEngine:
    def __init__(self, case_manager: Optional[CaseManager] = None):
        self.actions: Dict[str, Action] = {}
        self.simulate_mode = True
        self.case_manager = case_manager

    def register_action(self, action: Action):
        self.actions[action.name] = action

    def execute_action(self, action_name: str, context: Dict[str, Any], user_id: int, case_id: int) -> Dict[str, Any]:
        if action_name not in self.actions:
            return {"status": "error", "message": f"Unknown action: {action_name}"}

        action = self.actions[action_name]
        
        # Inject simulate config into context
        context["simulate_mode"] = self.simulate_mode
        context["case_id"] = case_id
        
        try:
            logger.info(f"Executing action {action_name} [Simulate={self.simulate_mode}]")
            result = action.execute(context)
            
            # Log to DB if manager exists
            if self.case_manager:
                log_details = {
                    "context": {k:v for k,v in context.items() if k not in ["manager", "case_manager"]}, 
                    "result": result,
                    "simulated": self.simulate_mode
                }
                # Assuming Action logs are mapped explicitly to the case manager
                target = context.get("target", "unknown")
                self.case_manager.log_action(case_id, user_id, action_name, target, json.dumps(log_details), result.get("status", "unknown"))

            return result
        except Exception as e:
            logger.error(f"Action execution failed: {e}")
            failure_result = {"status": "error", "message": f"Execution failed: {str(e)}"}
            if self.case_manager:
                self.case_manager.log_action(case_id, user_id, action_name, context.get("target", "unknown"), json.dumps({"error": str(e)}), "error")
            return failure_result
