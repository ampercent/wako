import pytest
import time
from fastapi.testclient import TestClient
from api import app, case_manager, ingestion_service
import os
from tempfile import NamedTemporaryFile
import json

client = TestClient(app)

@pytest.fixture(scope="module", autouse=True)
def setup_test_db():
    with NamedTemporaryFile(delete=False) as f:
        db_path = f.name
    case_manager.db.db_path = db_path
    case_manager.db._init_db()
    
    # Needs a real user for token gen
    client.post("/auth/register", json={"username": "detectuser", "password": "123", "role": "analyst"})
    
    yield
    try:
        os.unlink(db_path)
    except: pass

def get_token():
    return client.post("/auth/login", json={"username": "detectuser", "password": "123"}).json()["access_token"]

def test_engine_operators():
    from core.rules.engine import DetectionEngine
    engine = DetectionEngine()
    
    event = {"process_name": "cmd.exe", "pid": 1337, "has_network": True, "score": 85.5}
    
    # Equal match
    assert engine.evaluate_rule({"conditions": [{"field": "process_name", "operator": "==", "value": "cmd.exe"}]}, event) == True
    # Insensitive match
    assert engine.evaluate_rule({"conditions": [{"field": "process_name", "operator": "==", "value": "CMD.EXE"}]}, event) == True
    # Not equal
    assert engine.evaluate_rule({"conditions": [{"field": "process_name", "operator": "!=", "value": "powershell.exe"}]}, event) == True
    # Boolean logic
    assert engine.evaluate_rule({"conditions": [{"field": "has_network", "operator": "==", "value": True}]}, event) == True
    # Numeric Greater
    assert engine.evaluate_rule({"conditions": [{"field": "score", "operator": ">", "value": 80}]}, event) == True
    # Numeric Less Failed
    assert engine.evaluate_rule({"conditions": [{"field": "score", "operator": "<", "value": 80}]}, event) == False
    # List Inclusion
    assert engine.evaluate_rule({"conditions": [{"field": "process_name", "operator": "in", "value": ["powershell.exe", "cmd.exe"]}]}, event) == True
    # Missing Field
    assert engine.evaluate_rule({"conditions": [{"field": "missing_key", "operator": "==", "value": 1}]}, event) == False

def test_crud_rules():
    token = get_token()
    headers = {"Authorization": f"Bearer {token}"}
    
    resp = client.post("/rules", json={
        "id": "HighSeverityShell",
        "severity": "HIGH",
        "conditions": [{"field": "process", "operator": "==", "value": "sh"}]
    }, headers=headers)
    assert resp.status_code == 200
    rule_id = resp.json()["rule_id"]
    
    rules = client.get("/rules", headers=headers).json()["rules"]
    assert len(rules) == 1
    assert rules[0]["name"] == "HighSeverityShell"
    
    # Cleanup for clean state
    client.delete(f"/rules/{rule_id}", headers=headers)
    assert len(client.get("/rules", headers=headers).json()["rules"]) == 0

def test_ingestion_and_auto_case():
    token = get_token()
    headers = {"Authorization": f"Bearer {token}"}
    
    # 1. Register a rule
    client.post("/rules", json={
        "name": "malicious_ps",
        "severity": "CRITICAL",
        "conditions": [{"field": "process_name", "operator": "==", "value": "powershell.exe"}]
    }, headers=headers)
    
    # 2. Fire Event
    resp = client.post("/ingest/event", json={
        "type": "process_start",
        "source": "host_web_1",
        "data": {
            "process_name": "powershell.exe",
            "cmdline": "powershell.exe -enc ZXZpbA=="
        }
    }, headers=headers)
    
    assert resp.status_code == 200
    data = resp.json()
    assert data["matches"] == 1
    assert data["severity"] == "CRITICAL"
    assert data["case_id"] is not None
    case_id = data["case_id"]
    
    # 3. Verify Auto Case created
    case = case_manager.get_case(case_id)
    assert case["name"] == "Auto-Case: host_web_1"
    
    # 4. Verify stream event injected to case state
    state = case.get("session_state")
    assert "stream_events" in state
    assert len(state["stream_events"]) == 1
    assert state["stream_events"][0]["rule"] == "malicious_ps"
    
    # 5. Fire second event, verify appended to same case
    resp2 = client.post("/ingest/event", json={
        "type": "process_start",
        "source": "host_web_1",
        "data": {
            "process_name": "powershell.exe",
            "cmdline": "powershell -c whoami"
        }
    }, headers=headers)
    assert resp2.json()["case_id"] == case_id # Should map identical
    
    case = case_manager.get_case(case_id)
    assert len(case.get("session_state").get("stream_events")) == 2

def test_alert_stream():
    token = get_token()
    headers = {"Authorization": f"Bearer {token}"}
    
    resp = client.get("/alerts/stream", headers=headers)
    assert resp.status_code == 200
    stream = resp.json()["stream"]
    assert len(stream) >= 2 # From the previous test
    assert stream[0]["severity"] == "CRITICAL"

def test_performance_evaluation():
    from core.rules.engine import DetectionEngine
    engine = DetectionEngine()
    
    # Create 5 rules
    rules = []
    for i in range(5):
        rules.append({
            "name": f"rule_{i}",
            "conditions": [
                {"field": "process_name", "operator": "in", "value": ["bad.exe", "evil.exe"]},
                {"field": "score", "operator": ">", "value": 50}
            ]
        })
        
    event = {"process_name": "evil.exe", "score": 90}
    
    # Run 1000 evaluations
    start_time = time.time()
    for _ in range(1000):
        engine.evaluate_all(rules, event)
    total_time_ms = (time.time() - start_time) * 1000
    
    avg_per_eval_ms = total_time_ms / 1000
    # Must comfortably sit < 10ms (dict parsing is around 0.05ms normally)
    assert avg_per_eval_ms < 10
