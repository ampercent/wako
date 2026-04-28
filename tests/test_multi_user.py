import pytest
from fastapi.testclient import TestClient
from api import app
from case_management.manager import CaseManager
import os
from tempfile import NamedTemporaryFile

client = TestClient(app)

@pytest.fixture(scope="module", autouse=True)
def setup_test_db():
    # Use a temporary DB for tests so we don't pollute the real DB
    with NamedTemporaryFile(delete=False) as f:
        db_path = f.name
    
    # Overwrite the db_path in the global app dependency
    from api import case_manager
    case_manager.db.db_path = db_path
    case_manager.db._init_db()
    
    yield
    
    try:
        os.unlink(db_path)
    except:
        pass

def test_register_and_login():
    # 1. Register
    response = client.post("/auth/register", json={
        "username": "testuser1",
        "password": "mypassword123",
        "role": "analyst"
    })
    assert response.status_code == 200
    data = response.json()
    assert data["username"] == "testuser1"
    
    # Register duplicate fails
    response2 = client.post("/auth/register", json={
        "username": "testuser1",
        "password": "mypassword123"
    })
    assert response2.status_code == 400

    # 2. Login
    response3 = client.post("/auth/login", json={
        "username": "testuser1",
        "password": "mypassword123"
    })
    assert response3.status_code == 200
    assert "access_token" in response3.json()

    # Login fail
    response4 = client.post("/auth/login", json={
        "username": "testuser1",
        "password": "wrong"
    })
    assert response4.status_code == 401

def test_authenticated_case_creation_and_access():
    # Get token
    login_resp = client.post("/auth/login", json={"username": "testuser1", "password": "mypassword123"})
    token = login_resp.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Create Case
    create_resp = client.post("/cases", json={"name": "Auth Case 1"}, headers=headers)
    assert create_resp.status_code == 200
    case_id = create_resp.json().get("id")

    # Access Case
    get_resp = client.get(f"/cases/{case_id}", headers=headers)
    assert get_resp.status_code == 200
    assert get_resp.json()["name"] == "Auth Case 1"

    # Register User 2
    client.post("/auth/register", json={"username": "testuser2", "password": "pw"})
    token2 = client.post("/auth/login", json={"username": "testuser2", "password": "pw"}).json()["access_token"]
    headers2 = {"Authorization": f"Bearer {token2}"}

    # User 2 tries to access User 1's case -> 403 Forbidden
    get_fail = client.get(f"/cases/{case_id}", headers=headers2)
    assert get_fail.status_code == 403

def test_case_sharing():
    login_resp = client.post("/auth/login", json={"username": "testuser1", "password": "mypassword123"})
    headers1 = {"Authorization": f"Bearer {login_resp.json()['access_token']}"}
    
    login_resp2 = client.post("/auth/login", json={"username": "testuser2", "password": "pw"})
    headers2 = {"Authorization": f"Bearer {login_resp2.json()['access_token']}"}

    # Need a case
    create_resp = client.post("/cases", json={"name": "Shared Case"}, headers=headers1)
    case_id = create_resp.json().get("id")

    # Share
    share_resp = client.post(f"/cases/{case_id}/share", json={"username": "testuser2", "role": "analyst"}, headers=headers1)
    assert share_resp.status_code == 200

    # User 2 should now have access
    get_resp = client.get(f"/cases/{case_id}", headers=headers2)
    assert get_resp.status_code == 200

def test_comments_and_activity():
    login_resp = client.post("/auth/login", json={"username": "testuser1", "password": "mypassword123"})
    headers = {"Authorization": f"Bearer {login_resp.json()['access_token']}"}

    case_id = client.post("/cases", json={"name": "Comment Case"}, headers=headers).json().get("id")

    # Add comment
    comm_resp = client.post(f"/cases/{case_id}/comments", json={
        "entity_type": "process",
        "entity_id": "1234",
        "comment": "Suspicious powershell"
    }, headers=headers)
    assert comm_resp.status_code == 200

    # Check comments in case
    get_resp = client.get(f"/cases/{case_id}", headers=headers)
    comments = get_resp.json()["comments"]
    assert len(comments) == 1
    assert comments[0]["comment"] == "Suspicious powershell"
    assert comments[0]["username"] == "testuser1"

    # Check activity
    act_resp = client.get(f"/cases/{case_id}/activity", headers=headers)
    assert act_resp.status_code == 200
    activities = act_resp.json().get("activity")
    assert any("comment_added" in a["action"] for a in activities)

def test_case_dashboard_summary():
    headers = {"Authorization": f"Bearer {client.post('/auth/login', json={'username': 'testuser1', 'password': 'mypassword123'}).json()['access_token']}"}
    case_id = client.post("/cases", json={"name": "Summary Case"}, headers=headers).json().get("id")
    
    # Mock alerts state update
    # Use internal manager for quick setup
    from api import case_manager
    case_manager.update_state(case_id, alerts=[{"Severity": "HIGH", "Process Name": "bad.exe"}])

    sum_resp = client.get(f"/cases/{case_id}/summary", headers=headers)
    assert sum_resp.status_code == 200
    data = sum_resp.json()
    assert data["alert_count"] == 1
    assert "bad.exe" in data["high_risk_processes"]

def test_legacy_bypass_works():
    # Calling /cases without header
    resp = client.post("/cases", json={"name": "Legacy Case"})
    assert resp.status_code == 200
    case_id = resp.json().get("id")

    # Calling get case without header
    get_resp = client.get(f"/cases/{case_id}")
    assert get_resp.status_code == 200
    assert get_resp.json()["name"] == "Legacy Case"
