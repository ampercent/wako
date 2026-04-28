import sqlite3
import json
import logging
from pathlib import Path
from typing import Dict, List, Any, Optional

logger = logging.getLogger(__name__)

class CaseDatabase:
    def __init__(self, db_path: str = "C:/Major_Project/cases.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _get_conn(self):
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        with self._get_conn() as conn:
            # Users Table
            conn.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password TEXT NOT NULL,
                    role TEXT DEFAULT 'analyst'
                )
            ''')
            # Cases Table
            conn.execute('''
                CREATE TABLE IF NOT EXISTS cases (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    description TEXT,
                    dump_file TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    status TEXT DEFAULT 'OPEN',
                    alerts_state TEXT,
                    timeline_state TEXT,
                    graph_state TEXT,
                    owner_id INTEGER,
                    session_state TEXT,
                    FOREIGN KEY (owner_id) REFERENCES users(id)
                )
            ''')
            # Case Users (Sharing)
            conn.execute('''
                CREATE TABLE IF NOT EXISTS case_users (
                    case_id INTEGER NOT NULL,
                    user_id INTEGER NOT NULL,
                    role TEXT NOT NULL,
                    PRIMARY KEY (case_id, user_id),
                    FOREIGN KEY (case_id) REFERENCES cases(id),
                    FOREIGN KEY (user_id) REFERENCES users(id)
                )
            ''')
            # Comments Table
            conn.execute('''
                CREATE TABLE IF NOT EXISTS comments (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    case_id INTEGER NOT NULL,
                    user_id INTEGER NOT NULL,
                    entity_type TEXT NOT NULL,
                    entity_id TEXT NOT NULL,
                    comment TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (case_id) REFERENCES cases(id),
                    FOREIGN KEY (user_id) REFERENCES users(id)
                )
            ''')
            # Notes Table
            conn.execute('''
                CREATE TABLE IF NOT EXISTS notes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    case_id INTEGER NOT NULL,
                    user_id INTEGER,
                    entity_type TEXT NOT NULL, -- e.g., 'process', 'event', 'case'
                    entity_id TEXT NOT NULL,   -- e.g., 'PID_1234', 'event_1'
                    note_text TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (case_id) REFERENCES cases(id),
                    FOREIGN KEY (user_id) REFERENCES users(id)
                )
            ''')
            # Activity Log Table
            conn.execute('''
                CREATE TABLE IF NOT EXISTS activity_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    case_id INTEGER NOT NULL,
                    user_id INTEGER NOT NULL,
                    action TEXT NOT NULL,
                    details TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (case_id) REFERENCES cases(id),
                    FOREIGN KEY (user_id) REFERENCES users(id)
                )
            ''')
            # Action Execution Log Table
            conn.execute('''
                CREATE TABLE IF NOT EXISTS action_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    case_id INTEGER NOT NULL,
                    user_id INTEGER NOT NULL,
                    action_name TEXT NOT NULL,
                    target TEXT NOT NULL,
                    result TEXT,
                    status TEXT NOT NULL,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (case_id) REFERENCES cases(id),
                    FOREIGN KEY (user_id) REFERENCES users(id)
                )
            ''')
            # Detection Rules Table
            conn.execute('''
                CREATE TABLE IF NOT EXISTS detection_rules (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    action TEXT,
                    conditions_json TEXT NOT NULL,
                    is_active BOOLEAN DEFAULT 1
                )
            ''')
            # Alert Stream Table
            conn.execute('''
                CREATE TABLE IF NOT EXISTS alert_stream (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    case_id INTEGER,
                    rule_id INTEGER,
                    event_data TEXT,
                    severity TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            # Saved Queries Table
            conn.execute('''
                CREATE TABLE IF NOT EXISTS saved_queries (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    name TEXT NOT NULL,
                    query TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users(id)
                )
            ''')
            conn.commit()

            # Ensure default admin user exists
            from core.security import get_password_hash
            cursor = conn.execute("SELECT id FROM users WHERE username='admin'")
            if not cursor.fetchone():
                admin_pw = get_password_hash("admin")
                conn.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", ("admin", admin_pw, "admin"))
                conn.commit()


    def create_case(self, name: str, description: str, dump_file: str, owner_id: int = 1) -> int:
        with self._get_conn() as conn:
            cursor = conn.execute(
                'INSERT INTO cases (name, description, dump_file, owner_id) VALUES (?, ?, ?, ?)',
                (name, description, dump_file, owner_id)
            )
            case_id = cursor.lastrowid
            # Also insert activity log
            conn.execute(
                "INSERT INTO activity_log (case_id, user_id, action, details) VALUES (?, ?, ?, ?)",
                (case_id, owner_id, "case_created", json.dumps({"name": name}))
            )
            conn.commit()
            return case_id

    def get_case(self, case_id: int) -> Optional[Dict[str, Any]]:
        with self._get_conn() as conn:
            cursor = conn.execute('SELECT * FROM cases WHERE id = ?', (case_id,))
            row = cursor.fetchone()
            if row:
                return dict(row)
            return None

    def get_all_cases(self) -> List[Dict[str, Any]]:
        with self._get_conn() as conn:
            cursor = conn.execute('SELECT id, name, description, dump_file, created_at, status FROM cases ORDER BY id DESC')
            return [dict(row) for row in cursor.fetchall()]

    def update_case_state(self, case_id: int, alerts: Any = None, timeline: Any = None, graph: Any = None, session_state: Any = None):
        updates = []
        params = []
        if alerts is not None:
            updates.append("alerts_state = ?")
            params.append(json.dumps(alerts))
        if timeline is not None:
            updates.append("timeline_state = ?")
            params.append(json.dumps(timeline))
        if graph is not None:
            updates.append("graph_state = ?")
            params.append(json.dumps(graph))
        if session_state is not None:
            updates.append("session_state = ?")
            params.append(json.dumps(session_state))
            
        if not updates:
            return

        params.append(case_id)
        query = f"UPDATE cases SET {', '.join(updates)} WHERE id = ?"
        with self._get_conn() as conn:
            conn.execute(query, tuple(params))
            conn.commit()

    def add_note(self, case_id: int, entity_type: str, entity_id: str, note_text: str, user_id: int = 1) -> int:
        with self._get_conn() as conn:
            cursor = conn.execute(
                'INSERT INTO notes (case_id, user_id, entity_type, entity_id, note_text) VALUES (?, ?, ?, ?, ?)',
                (case_id, user_id, entity_type, entity_id, note_text)
            )
            conn.commit()
            return cursor.lastrowid

    def get_notes(self, case_id: int, entity_type: str = None, entity_id: str = None) -> List[Dict[str, Any]]:
        query = 'SELECT * FROM notes WHERE case_id = ?'
        params = [case_id]
        
        if entity_type:
            query += ' AND entity_type = ?'
            params.append(entity_type)
        if entity_id:
            query += ' AND entity_id = ?'
            params.append(entity_id)
            
        query += ' ORDER BY created_at DESC'
        
        with self._get_conn() as conn:
            cursor = conn.execute(query, tuple(params))
            return [dict(row) for row in cursor.fetchall()]

    # Multi-User Additions

    def get_user_by_username(self, username: str) -> Optional[Dict[str, Any]]:
        with self._get_conn() as conn:
            cursor = conn.execute('SELECT * FROM users WHERE username = ?', (username,))
            row = cursor.fetchone()
            if row:
                return dict(row)
            return None

    def create_user(self, username: str, password_hash: str, role: str = 'analyst') -> int:
        with self._get_conn() as conn:
            cursor = conn.execute(
                'INSERT INTO users (username, password, role) VALUES (?, ?, ?)',
                (username, password_hash, role)
            )
            conn.commit()
            return cursor.lastrowid

    def share_case(self, case_id: int, user_id: int, role: str):
        with self._get_conn() as conn:
            conn.execute(
                'INSERT OR REPLACE INTO case_users (case_id, user_id, role) VALUES (?, ?, ?)',
                (case_id, user_id, role)
            )
            conn.commit()

    def get_case_users(self, case_id: int) -> List[Dict[str, Any]]:
        with self._get_conn() as conn:
            cursor = conn.execute(
                'SELECT u.id, u.username, u.role as global_role, cu.role as case_role FROM case_users cu JOIN users u ON cu.user_id = u.id WHERE cu.case_id = ?',
                (case_id,)
            )
            return [dict(row) for row in cursor.fetchall()]

    def add_comment(self, case_id: int, user_id: int, entity_type: str, entity_id: str, comment: str) -> int:
        with self._get_conn() as conn:
            cursor = conn.execute(
                'INSERT INTO comments (case_id, user_id, entity_type, entity_id, comment) VALUES (?, ?, ?, ?, ?)',
                (case_id, user_id, entity_type, entity_id, comment)
            )
            conn.commit()
            return cursor.lastrowid

    def get_comments(self, case_id: int, entity_type: str = None, entity_id: str = None) -> List[Dict[str, Any]]:
        query = 'SELECT c.*, u.username FROM comments c JOIN users u ON c.user_id = u.id WHERE c.case_id = ?'
        params = [case_id]
        if entity_type:
            query += ' AND c.entity_type = ?'
            params.append(entity_type)
        if entity_id:
            query += ' AND c.entity_id = ?'
            params.append(entity_id)
        query += ' ORDER BY c.created_at DESC'
        with self._get_conn() as conn:
            cursor = conn.execute(query, tuple(params))
            return [dict(row) for row in cursor.fetchall()]

    def log_activity(self, case_id: int, user_id: int, action: str, details: str):
        with self._get_conn() as conn:
            conn.execute(
                'INSERT INTO activity_log (case_id, user_id, action, details) VALUES (?, ?, ?, ?)',
                (case_id, user_id, action, details)
            )
            conn.commit()

    def get_activity_log(self, case_id: int) -> List[Dict[str, Any]]:
        with self._get_conn() as conn:
            cursor = conn.execute(
                'SELECT a.*, u.username FROM activity_log a JOIN users u ON a.user_id = u.id WHERE a.case_id = ? ORDER BY a.timestamp DESC',
                (case_id,)
            )
            return [dict(row) for row in cursor.fetchall()]

    def log_action(self, case_id: int, user_id: int, action_name: str, target: str, result: str, status: str):
        with self._get_conn() as conn:
            conn.execute(
                'INSERT INTO action_logs (case_id, user_id, action_name, target, result, status) VALUES (?, ?, ?, ?, ?, ?)',
                (case_id, user_id, action_name, target, result, status)
            )
            conn.commit()

    def get_action_logs(self, case_id: int) -> List[Dict[str, Any]]:
        with self._get_conn() as conn:
            cursor = conn.execute(
                'SELECT a.*, u.username FROM action_logs a JOIN users u ON a.user_id = u.id WHERE a.case_id = ? ORDER BY a.timestamp DESC',
                (case_id,)
            )
            return [dict(row) for row in cursor.fetchall()]

    # --- Continuous Monitoring Tracking ---
    
    def create_rule(self, name: str, severity: str, action: str, conditions_json: str) -> int:
        with self._get_conn() as conn:
            cursor = conn.execute(
                'INSERT INTO detection_rules (name, severity, action, conditions_json) VALUES (?, ?, ?, ?)',
                (name, severity, action, conditions_json)
            )
            conn.commit()
            return cursor.lastrowid

    def get_rules(self, active_only: bool = True) -> List[Dict[str, Any]]:
        with self._get_conn() as conn:
            query = 'SELECT * FROM detection_rules'
            if active_only: query += ' WHERE is_active = 1'
            cursor = conn.execute(query)
            return [dict(row) for row in cursor.fetchall()]

    def delete_rule(self, rule_id: int):
        with self._get_conn() as conn:
            conn.execute('DELETE FROM detection_rules WHERE id = ?', (rule_id,))
            conn.commit()

    def append_alert_stream(self, case_id: int, rule_id: int, event_data: str, severity: str):
        with self._get_conn() as conn:
            conn.execute(
                'INSERT INTO alert_stream (case_id, rule_id, event_data, severity) VALUES (?, ?, ?, ?)',
                (case_id, rule_id, event_data, severity)
            )
            conn.commit()

    def get_alert_stream(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._get_conn() as conn:
            cursor = conn.execute('SELECT * FROM alert_stream ORDER BY timestamp DESC LIMIT ?', (limit,))
            return [dict(row) for row in cursor.fetchall()]

    # --- Hunting Engine ---

    def save_query(self, user_id: int, name: str, query: str) -> int:
        with self._get_conn() as conn:
            cursor = conn.execute(
                'INSERT INTO saved_queries (user_id, name, query) VALUES (?, ?, ?)',
                (user_id, name, query)
            )
            conn.commit()
            return cursor.lastrowid

    def get_saved_queries(self, user_id: int) -> List[Dict[str, Any]]:
        with self._get_conn() as conn:
            cursor = conn.execute(
                'SELECT * FROM saved_queries WHERE user_id = ? ORDER BY created_at DESC',
                (user_id,)
            )
            return [dict(row) for row in cursor.fetchall()]

    def delete_query(self, query_id: int, user_id: int):
        with self._get_conn() as conn:
            conn.execute('DELETE FROM saved_queries WHERE id = ? AND user_id = ?', (query_id, user_id))
            conn.commit()
