import pytest
from fastapi.testclient import TestClient
from api import app, action_engine
from case_management.manager import CaseManager
import pandas as pd
from core.actions.recommender import recommend_actions
import os
from tempfile import NamedTemporaryFile

client = TestClient(app)

@pytest.fixture(scope="module", autouse=True)
def setup_test_db():
    with NamedTemporaryFile(delete=False) as f:
        db_path = f.name
    
    from api import case_manager
    case_manager.db.db_path = db_path
    case_manager.db._init_db()
    
    yield
    
    try:
        os.unlink(db_path)
    except:
        pass

@pytest.fixture(scope="module", autouse=True)
def setup_test_auth_and_case(setup_test_db):
    client.post("/auth/register", json={"username": "actionanalyst", "password": "123", "role": "analyst"})
    client.post("/auth/register", json={"username": "actionviewer", "password": "123", "role": "viewer"})

def get_token(username):
    resp = client.post("/auth/login", json={"username": username, "password": "123"})
    return resp.json()["access_token"]

def test_permissions_viewer_blocked():
    token = get_token("actionviewer")
    headers = {"Authorization": f"Bearer {token}"}
    
    # Needs a valid case context to hit the permission check, actually viewer check happens before case validation
    resp = client.post("/actions/execute", json={
        "action": "block_ip",
        "target": "8.8.8.8",
        "case_id": 999
    }, headers=headers)
    assert resp.status_code == 403
    assert "Viewers cannot execute actions" in resp.json()["detail"]

def test_execute_simulate_mode_success():
    token = get_token("actionanalyst")
    headers = {"Authorization": f"Bearer {token}"}
    
    # Create a real case
    case_resp = client.post("/cases", json={"name": "Action Test Case"}, headers=headers)
    case_id = case_resp.json()["id"]

    resp = client.post("/actions/execute", json={
        "action": "block_ip",
        "target": "8.8.8.8",
        "case_id": case_id,
        "simulate": True
    }, headers=headers)
    
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "success"
    assert "[SIMULATION]" in data["message"]
    
    # Verify log was created
    log_resp = client.get(f"/cases/{case_id}/actions", headers=headers)
    assert log_resp.status_code == 200
    logs = log_resp.json().get("logs", [])
    assert len(logs) == 1
    assert logs[0]["action_name"] == "block_ip"
    assert logs[0]["target"] == "8.8.8.8"

def test_execute_export_report():
    token = get_token("actionanalyst")
    headers = {"Authorization": f"Bearer {token}"}
    case_id = client.post("/cases", json={"name": "Exp"}, headers=headers).json()["id"]
    
    resp = client.post("/actions/execute", json={
        "action": "export_evidence",
        "target": "case",
        "case_id": case_id
    }, headers=headers)
    assert resp.status_code == 200
    assert "Exported" in resp.json()["message"] or "exported successfully" in resp.json()["message"]

def test_recommendations_logic():
    df_corr = pd.DataFrame([{
        "PID": 1234,
        "Process Name": "bad.exe",
        "Severity": "HIGH",
        "has_injection": True,
        "has_network": True
    }])
    df_tl = pd.DataFrame([{
        "timestamp": "2026-04-10",
        "description": "Suspicious execution communicating with External IP 8.8.8.8"
    }])
    
    recs = recommend_actions(df_corr, df_tl)
    actions = [r["action"] for r in recs]
    assert "terminate_process" in actions
    assert "tag_malicious" in actions
    assert "block_ip" in actions
    
def test_recommendations_api():
    token = get_token("actionanalyst")
    headers = {"Authorization": f"Bearer {token}"}
    
    # Manually seed a case with raw states
    case_id = client.post("/cases", json={"name": "Rec Test Case"}, headers=headers).json()["id"]
    from api import case_manager
    case_manager.update_state(case_id, alerts=[{
        "PID": 4444, "Process Name": "evil.exe", "Severity": "HIGH", "has_injection": True
    }])
    
    resp = client.get(f"/actions/recommendations/{case_id}", headers=headers)
    assert resp.status_code == 200
    recs = resp.json()["recommendations"]
    assert len(recs) == 1
    assert recs[0]["action"] == "terminate_process"
