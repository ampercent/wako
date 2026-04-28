import pandas as pd
from typing import List, Dict, Any
from .parser import QueryParser
import logging

logger = logging.getLogger(__name__)

class QueryEngine:
    """ Evaluates parsed AST representations against case data. """
    def __init__(self, case_manager):
        self.case_manager = case_manager
        self.parser = QueryParser()

    def execute(self, query_string: str) -> List[Dict[str, Any]]:
        """ Cross-case execution leveraging cached memory structs where possible. """
        ast = self.parser.parse(query_string)
        if not ast:
            return []

        # Pull active cases and flatten their streams
        # Filtering only active recent cases for performance (<200ms bounds)
        cases = self.case_manager.get_all_cases()
        
        flat_records = []
        for case in cases:
            # Rehydrate case states securely (they are stored as JSON strings)
            # manager.get_case auto loads them!
            full_case = self.case_manager.get_case(case["id"])
            if not full_case: continue
            
            base_meta = {
                "case_id": full_case["id"],
                "source": full_case.get("name") # Using name as host marker historically
            }

            # 1. Timeline
            tl = full_case.get("timeline_state") or []
            for evt in tl:
                flat_records.append({**evt, **base_meta, "data_source": "timeline"})

            # 2. Streams
            sess = full_case.get("session_state") or {}
            streams = sess.get("stream_events") or []
            for st in streams:
                event_wrap = st.get("event", {})
                flat_records.append({
                    "process_name": event_wrap.get("process_name", ""),
                    "pid": event_wrap.get("pid"),
                    "event_type": event_wrap.get("type", ""),
                    "severity": st.get("rule", ""), # Approximated
                    **base_meta,
                    **event_wrap,
                    "data_source": "stream"
                })

            # 3. Alerts
            alerts = full_case.get("alerts_state") or []
            for al in alerts:
                # Align naming
                flat_records.append({
                    "process_name": al.get("Process Name", ""),
                    "pid": al.get("PID"),
                    "severity": al.get("Severity", ""),
                    "event_type": "alert",
                    **base_meta,
                    **al,
                    "data_source": "alert"
                })

        if not flat_records:
            return []

        df = pd.DataFrame(flat_records)
        mask = self._eval_node(ast, df)
        
        if mask is None:
            return []

        result_df = df[mask]
        
        # Format back into list of dicts, cleaning NaN
        result_df = result_df.where(pd.notnull(result_df), None)
        return result_df.to_dict("records")

    def _eval_node(self, node: Dict[str, Any], df: pd.DataFrame) -> Any:
        # returns boolean Series
        if not node: return None
        
        if node["type"] == "logic":
            left_mask = self._eval_node(node["left"], df)
            right_mask = self._eval_node(node["right"], df)
            
            if left_mask is None and right_mask is None: return None
            if left_mask is None: return right_mask
            if right_mask is None: return left_mask

            if node["op"] == "AND":
                return left_mask & right_mask
            elif node["op"] == "OR":
                return left_mask | right_mask

        elif node["type"] == "condition":
            f = node["field"]
            if f not in df.columns:
                # If column isn't there, we just say it's false for every row 
                return pd.Series(False, index=df.index)
            
            op = node["op"]
            # Convert series to string generically for safety
            val = node["value"]
            s = df[f].fillna("").astype(str).str.lower()
            
            if op == "==":
                return s == str(val).lower()
            elif op == "!=":
                return s != str(val).lower()
            elif op == ">":
                return pd.to_numeric(df[f], errors="coerce") > float(val)
            elif op == "<":
                return pd.to_numeric(df[f], errors="coerce") < float(val)
            elif op == ">=":
                return pd.to_numeric(df[f], errors="coerce") >= float(val)
            elif op == "<=":
                return pd.to_numeric(df[f], errors="coerce") <= float(val)
            elif op in ("IN", "in") and isinstance(val, list):
                val_list = [str(x).lower() for x in val]
                return s.isin(val_list)

        return None
