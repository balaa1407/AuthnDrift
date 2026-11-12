"""
AuthDrift Web API & Backend Integration Tests.
Validates FastAPI endpoints serving the dashboard and external integrations,
including alert types, IP separation, and per-user location baselines.
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

    # Verify IP address field exists in reconstructed journey events
    journey = data["journeys"][0]
    assert "events" in journey
    assert "ip_address" in journey["events"][0]

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
        assert "alert_type" in alert
        assert alert["alert_type"] == "ASSURANCE_DRIFT"
        assert "context_evidence" in alert
        assert "location_status" in alert["context_evidence"]
        assert "primary_location" in alert["context_evidence"]


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
                "ipAddress": "192.168.1.88",
                "details": {"username": "zack", "auth_method": "passkey"}
            },
            {
                "id": "custom-2",
                "time": 1730300415000,
                "type": "LOGIN",
                "ipAddress": "192.168.1.88",
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
    assert data["alerts"][0]["alert_type"] == "ASSURANCE_DRIFT"
    assert data["alerts"][0]["context_evidence"]["ip_address"] == "192.168.1.88"


def test_api_health_endpoint():
    resp = client.get("/api/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "HEALTHY"
    assert data["service"] == "AuthDrift"
    assert "uptime_seconds" in data
    assert "threat_intelligence" in data
    assert data["pipeline_ready"] is True


def test_api_threat_intel_lookup_endpoint():
    # Private IP lookup
    resp = client.get("/api/threat-intel/lookup?ip=192.168.1.1")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "PRIVATE"
    assert data["ip_address"] == "192.168.1.1"

    # Invalid IP lookup
    resp_invalid = client.get("/api/threat-intel/lookup?ip=not-an-ip")
    assert resp_invalid.status_code == 200
    data_invalid = resp_invalid.json()
    assert data_invalid["status"] == "UNKNOWN"


def test_api_threat_intel_scenarios_loading():
    # Load TC10 (Victor: Threat Intelligence Malicious Public IP)
    load_resp = client.post("/api/scenarios/tc10/load")
    assert load_resp.status_code == 200
    data = load_resp.json()
    assert len(data["journeys"]) == 1
    assert data["journeys"][0]["user_id"] == "victor"
    assert data["alerts"][0]["context_evidence"]["ip_address"] == "118.25.6.39"


def test_api_benchmark_case_studies_and_research_benchmark_scenarios():
    # 1. Verified Client Recovery Case Study (Bob on same laptop-01 and same IP)
    recov_resp = client.post("/api/scenarios/client_recovery/load")
    assert recov_resp.status_code == 200
    recov_data = recov_resp.json()
    assert len(recov_data["journeys"]) == 1
    assert recov_data["journeys"][0]["user_id"] == "bob"
    bob_alert = recov_data["alerts"][0]
    assert bob_alert["is_recovery_candidate"] is True
    assert bob_alert["drift_detected"] is False
    assert bob_alert["alert_type"] == "INFORMATIONAL"
    assert bob_alert["risk_assessment"]["score"] == 0

    # 2. Adversarial Assurance Downgrade Case Study (Carol on unfamiliar device & new IP)
    attack_resp = client.post("/api/scenarios/adversarial_downgrade/load")
    assert attack_resp.status_code == 200
    attack_data = attack_resp.json()
    assert len(attack_data["journeys"]) == 1
    assert attack_data["journeys"][0]["user_id"] == "carol"
    carol_alert = attack_data["alerts"][0]
    assert carol_alert["is_recovery_candidate"] is False
    assert carol_alert["drift_detected"] is True
    assert carol_alert["alert_type"] == "ASSURANCE_DRIFT"
    assert carol_alert["risk_assessment"]["score"] >= 70

    # 3. Research Paper Benchmark Dataset (Enhanced Enterprise Benchmark)
    research_resp = client.post("/api/scenarios/research_dataset/load")
    assert research_resp.status_code == 200
    research_data = research_resp.json()
    assert len(research_data["journeys"]) == 145
    assert len(research_data["alerts"]) == 145

    # Reset back to all scenarios
    client.post("/api/scenarios/all/load")


