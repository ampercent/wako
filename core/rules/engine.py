import json
import logging
from typing import Dict, Any, List

logger = logging.getLogger(__name__)

class DetectionEngine:
    def __init__(self):
        self.operators = {
            "==": lambda a, b: str(a).lower() == str(b).lower(),
            "!=": lambda a, b: str(a).lower() != str(b).lower(),
            ">": lambda a, b: float(a) > float(b) if self._is_num(a) and self._is_num(b) else False,
            "<": lambda a, b: float(a) < float(b) if self._is_num(a) and self._is_num(b) else False,
            "in": lambda a, b: str(a).lower() in str(b).lower() if b else False,
            "contains": lambda a, b: str(b).lower() in str(a).lower() if a else False,
        }

    def _is_num(self, val):
        try:
            float(val)
            return True
        except (ValueError, TypeError):
            return False

    def evaluate_rule(self, rule: Dict[str, Any], event: Dict[str, Any]) -> bool:
        """
        Evaluate a single JSON rule against an event dictionary.
        Returns True if all conditions match.
        Example rule conditions dict:
        [
            {"field": "process_name", "operator": "==", "value": "powershell.exe"},
            {"field": "severity", "operator": "in", "value": "high,critical"}
        ]
        """
        conditions = rule.get("conditions", [])
        if not conditions:
            return False

        if isinstance(conditions, str):
            try:
                conditions = json.loads(conditions)
            except:
                return False

        for cond in conditions:
            field = cond.get("field")
            op = cond.get("operator", "==")
            expected = cond.get("value")

            if not field or field not in event:
                return False
                
            actual = event.get(field)
            
            # Map booleans cleanly
            if isinstance(expected, bool):
                actual_bool = str(actual).lower() in ['true', '1', 'yes']
                if actual_bool != expected:
                    return False
                continue

            op_func = self.operators.get(op)
            if not op_func:
                logger.warning(f"Unknown operator: {op}")
                return False

            if op == "in" and isinstance(expected, list):
                # if expecting a list match
                match = any(op_func(actual, e) for e in expected)
                if not match: return False
            else:
                if not op_func(actual, expected):
                    return False

        return True

    def evaluate_all(self, rules: List[Dict[str, Any]], event: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Takes a list of active rules and evaluates them against an incoming event.
        Returns matched rules in <10ms.
        """
        matched = []
        for rule in rules:
            if self.evaluate_rule(rule, event):
                matched.append(rule)
        return matched
