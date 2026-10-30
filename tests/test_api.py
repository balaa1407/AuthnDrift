"""
AuthDrift Web API & Backend Integration Tests.
Validates FastAPI endpoints serving the dashboard and external integrations.
"""

from fastapi.testclient import TestClient
import pytest
from backend.api import app


client = TestClient(app)


def test_api_overview_endpoint():
    response = client.get("/api/overview")
    assert response.status_code == 200
    data = response.json()
    assert "metrics" in data
    assert "processed_events" in data["metrics"]
    assert "reconstructed_journeys" in data["metrics"]
    assert "detected_drift_alerts" in data["metrics"]


def test_api_journeys_endpoint_with_filtering():
    # Base fetch
    response = client.get("/api/journeys")
    assert response.status_code == 200
    data = response.json()
    assert "journeys" in data
    assert len(data["journeys"]) > 0

    # Filter by user
    filter_resp = client.get("/api/journeys?user_id=bob")
    assert filter_resp.status_code == 200
    filtered_data = filter_resp.json()
    assert all("bob" in j["user_id"].lower() for j in filtered_data["journeys"])


def test_api_alerts_endpoint():
    response = client.get("/api/alerts?drift_only=true")
    assert response.status_code == 200
    data = response.json()
    assert "alerts" in data
    for alert in data["alerts"]:
        assert alert["drift_detected"] is True


def test_api_scenario_loading():
    # Load TC02 (Bob: Passkey fallback)
    load_resp = client.post("/api/scenarios/tc02/load")
    assert load_resp.status_code == 200
    data = load_resp.json()
    assert len(data["journeys"]) == 1
    assert data["journeys"][0]["user_id"] == "bob"

    # Reset to all
    reset_resp = client.post("/api/scenarios/all/load")
    assert reset_resp.status_code == 200


def test_api_custom_pipeline_run():
    payload = {
        "provider": "keycloak",
        "events": [
            {
                "id": "custom-1",
                "time": 1730300400000,
                "type": "LOGIN_ERROR",
                "details": {"username": "zack", "auth_method": "passkey"}
            },
            {
                "id": "custom-2",
                "time": 1730300415000,
                "type": "LOGIN",
                "details": {"username": "zack", "auth_method": "password"}
            }
        ],
        "deduplicate": False
    }
    resp = client.post("/api/pipeline/run", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["journeys"]) == 1
    assert data["journeys"][0]["user_id"] == "zack"
    assert data["alerts"][0]["drift_detected"] is True

