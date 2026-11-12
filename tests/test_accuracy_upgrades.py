"""
AuthDrift: Unit and Regression Tests for Maximal Accuracy Upgrades.
Verifies:
1. Geodesic Haversine distance and impossible travel velocity evaluation.
2. Subnet continuity evaluation for routine DHCP IP address shifts.
3. NIST SP 800-63B Authenticator Assurance Level (AAL) & Cryptographic Boundary transitions.
4. Actionable SOC Remediation guidance generation.
5. End-to-end pipeline serialization of all new security telemetry fields.
"""

from datetime import datetime, timezone, timedelta
import pytest

from backend.correlation.velocity_analyzer import (
    haversine_distance_km,
    evaluate_travel_velocity,
    CITY_COORDINATES
)
from backend.assurance.assurance_model import AssuranceModel
from backend.models.event import AuthenticationEvent
from backend.models.detection import RiskSeverity
from backend.correlation.context_analyzer import ContextAnalyzer
from backend.alerts.alert_generator import AlertGenerator
from backend.pipeline.pipeline import AuthDriftPipeline


class TestVelocityAndGeodesicCalculations:
    """Tests for physical geodesic travel analysis."""

    def test_haversine_distance_bengaluru_frankfurt(self):
        coord_blr = CITY_COORDINATES["bengaluru"]
        coord_fra = CITY_COORDINATES["frankfurt"]
        dist = haversine_distance_km(coord_blr[0], coord_blr[1], coord_fra[0], coord_fra[1])
        # Bengaluru to Frankfurt is approximately 7,400 km
        assert 7000 < dist < 7800

    def test_impossible_travel_flagged_for_supersonic_displacement(self):
        t1 = datetime(2026, 11, 8, 10, 0, 0, tzinfo=timezone.utc)
        t2 = t1 + timedelta(seconds=30)  # 30 seconds later
        res = evaluate_travel_velocity(
            source_location="Bengaluru, IN",
            target_location="Frankfurt, DE",
            source_time=t1,
            target_time=t2
        )
        assert res is not None
        assert res["is_impossible_travel"] is True
        assert res["velocity_kmh"] > 500_000  # Physically impossible

    def test_plausible_travel_not_flagged(self):
        t1 = datetime(2026, 11, 8, 10, 0, 0, tzinfo=timezone.utc)
        t2 = t1 + timedelta(hours=12)  # 12 hours flight
        res = evaluate_travel_velocity(
            source_location="London, UK",
            target_location="New York, US",
            source_time=t1,
            target_time=t2
        )
        assert res is not None
        assert res["is_impossible_travel"] is False
        assert res["velocity_kmh"] < 900


class TestSubnetContinuityAndContext:
    """Tests for IPv4/IPv6 subnet continuity resolution."""

    def test_same_subnet_continuity_flagged(self):
        analyzer = ContextAnalyzer()
        t0 = datetime(2026, 11, 8, 10, 0, 0, tzinfo=timezone.utc)
        events = [
            AuthenticationEvent(
                event_id="e1",
                user_id="user1",
                timestamp=t0,
                event_type="LOGIN",
                authentication_method="passkey",
                outcome="SUCCESS",
                ip_address="192.168.1.10",
                device_id="dev1"
            ),
            AuthenticationEvent(
                event_id="e2",
                user_id="user1",
                timestamp=t0 + timedelta(minutes=5),
                event_type="REFRESH",
                authentication_method="passkey",
                outcome="SUCCESS",
                ip_address="192.168.1.45",
                device_id="dev1"
            )
        ]
        evidence = analyzer.analyze_journey_context(events, known_devices={"dev1"})
        assert len(evidence.context_anomalies) == 1
        anom = evidence.context_anomalies[0]
        assert anom.anomaly_type == "IP_CHANGE"
        assert anom.subnet_continuity is True

    def test_distinct_subnet_continuity_flagged_false(self):
        analyzer = ContextAnalyzer()
        t0 = datetime(2026, 11, 8, 10, 0, 0, tzinfo=timezone.utc)
        events = [
            AuthenticationEvent(
                event_id="e1",
                user_id="user1",
                timestamp=t0,
                event_type="LOGIN",
                authentication_method="passkey",
                outcome="SUCCESS",
                ip_address="192.168.1.10",
                device_id="dev1"
            ),
            AuthenticationEvent(
                event_id="e2",
                user_id="user1",
                timestamp=t0 + timedelta(minutes=5),
                event_type="REFRESH",
                authentication_method="passkey",
                outcome="SUCCESS",
                ip_address="10.200.5.8",
                device_id="dev1"
            )
        ]
        evidence = analyzer.analyze_journey_context(events, known_devices={"dev1"})
        assert len(evidence.context_anomalies) == 1
        anom = evidence.context_anomalies[0]
        assert anom.anomaly_type == "IP_CHANGE"
        assert anom.subnet_continuity is False


class TestNISTAssuranceModelUpgrades:
    """Tests for NIST SP 800-63B mapping and cryptographic boundary."""

    def test_nist_aal_levels(self):
        model = AssuranceModel()
        assert model.get_nist_aal("passkey") == "AAL3"
        assert model.get_nist_aal("totp") == "AAL2"
        assert model.get_nist_aal("password") == "AAL1"

    def test_phishing_resistance(self):
        model = AssuranceModel()
        assert model.is_phishing_resistant("passkey") is True
        assert model.is_phishing_resistant("fido2") is True
        assert model.is_phishing_resistant("password") is False
        assert model.is_phishing_resistant("sms_otp") is False

    def test_cryptographic_boundary_transition_description(self):
        model = AssuranceModel()
        desc = model.get_cryptographic_boundary_transition("passkey", "password")
        assert "AAL3 (Phishing-Resistant passkey)" in desc
        assert "AAL1 (Phishing-Vulnerable password)" in desc


class TestAlertRemediationAndPipelineSerialization:
    """Tests for SOC remediation playbook generation and JSON serialization."""

    def test_pipeline_serializes_maximal_accuracy_fields(self):
        pipeline = AuthDriftPipeline()
        t0 = "2026-11-08T10:00:00Z"
        t1 = "2026-11-08T10:00:25Z"

        raw_events = [
            {
                "time": t0,
                "type": "LOGIN_ERROR",
                "realmId": "master",
                "clientId": "account",
                "userId": "user-acc",
                "ipAddress": "192.168.1.10",
                "details": {
                    "auth_method": "webauthn-passwordless",
                    "device_id": "corporate-macbook-01",
                    "location": "Bengaluru, IN"
                }
            },
            {
                "time": t1,
                "type": "LOGIN",
                "realmId": "master",
                "clientId": "account",
                "userId": "user-acc",
                "ipAddress": "10.0.0.1",
                "details": {
                    "auth_method": "password",
                    "device_id": "unknown-linux-endpoint",
                    "location": "Frankfurt, DE"
                }
            }
        ]

        result = pipeline.process_raw_events(raw_events, provider="keycloak")
        serialized = result.to_dict()

        assert "alerts" in serialized
        assert len(serialized["alerts"]) == 1
        alert_dict = serialized["alerts"][0]

        # Check cryptographic boundary
        assert "cryptographic_boundary" in alert_dict
        assert alert_dict["cryptographic_boundary"] is not None
        assert "AAL3" in alert_dict["cryptographic_boundary"]
        assert "AAL1" in alert_dict["cryptographic_boundary"]

        # Check actionable remediation
        assert "actionable_remediation" in alert_dict
        assert len(alert_dict["actionable_remediation"]) >= 2
        remediations_str = " ".join(alert_dict["actionable_remediation"])
        assert "Revoke active session tokens" in remediations_str
        assert "Geodesic velocity violation" in remediations_str

        # Check context anomalies
        anomalies = alert_dict["context_anomalies"]
        impossible_anoms = [a for a in anomalies if a.get("is_impossible_travel") is True]
        assert len(impossible_anoms) >= 1
        assert impossible_anoms[0]["velocity_kmh"] is not None
        assert impossible_anoms[0]["velocity_kmh"] > 900


class TestPerson1Person2Integration:
    """Verifies cross-module integration between FallbackMemory, Subnet Continuity, and Calibration API."""

    def test_dhcp_same_subnet_continuity_with_fallback_memory(self):
        from backend.llm_calibration.fallback_memory import FallbackMemoryStore

        store = FallbackMemoryStore()
        store.register_baseline(
            user_id="dhcp_user",
            device_id="corporate-macbook-01",
            ip_address="192.168.10.50",
            location="Bengaluru, India"
        )
        pipeline = AuthDriftPipeline(fallback_memory=store)
        raw_events = [
            {
                "id": "e1",
                "time": "2026-11-12T10:00:00Z",
                "type": "LOGIN_ERROR",
                "userId": "dhcp_user",
                "sessionId": "sess-dhcp-1",
                "ipAddress": "192.168.10.50",
                "details": {
                    "auth_method": "passkey",
                    "device_id": "corporate-macbook-01",
                    "location": "Bengaluru, India"
                }
            },
            {
                "id": "e2",
                "time": "2026-11-12T10:00:20Z",
                "type": "LOGIN",
                "userId": "dhcp_user",
                "sessionId": "sess-dhcp-1",
                "ipAddress": "192.168.10.88",  # Same /24 DHCP lease
                "details": {
                    "auth_method": "password",
                    "device_id": "corporate-macbook-01",
                    "location": "Bengaluru, India"
                }
            }
        ]
        result = pipeline.process_raw_events(raw_events, provider="keycloak")
        assert len(result.alerts) == 1
        alert = result.alerts[0]
        assert alert.context_evidence.is_primary_ip_matched is True
        assert alert.context_evidence.is_primary_device_matched is True
        assert alert.is_recovery_candidate is True
        assert alert.case_category == "CASE_1_SAME_DEVICE_SAME_IP"
        assert alert.drift_detected is False

    def test_calibrate_journey_api_matches_exact_session_id(self):
        from fastapi.testclient import TestClient
        from backend.api import app

        client = TestClient(app)
        # Ingest two distinct sessions for the same user
        events = [
            {
                "id": "s1-e1",
                "time": "2026-11-12T10:00:00Z",
                "type": "LOGIN",
                "userId": "multi_user",
                "sessionId": "sess-clean",
                "ipAddress": "192.168.1.10",
                "details": {"auth_method": "passkey", "device_id": "corporate-macbook-01"}
            },
            {
                "id": "s2-e1",
                "time": "2026-11-12T12:00:00Z",
                "type": "LOGIN_ERROR",
                "userId": "multi_user",
                "sessionId": "sess-attack",
                "ipAddress": "192.168.1.10",
                "details": {"auth_method": "passkey", "device_id": "corporate-macbook-01"}
            },
            {
                "id": "s2-e2",
                "time": "2026-11-12T12:00:20Z",
                "type": "LOGIN",
                "userId": "multi_user",
                "sessionId": "sess-attack",
                "ipAddress": "203.0.113.99",
                "details": {"auth_method": "password", "device_id": "rogue-box"}
            }
        ]
        run_resp = client.post("/api/pipeline/run", json={"provider": "keycloak", "events": events})
        assert run_resp.status_code == 200

        calib_clean = client.post(
            "/api/llm/calibrate-journey",
            json={"user_id": "multi_user", "session_id": "sess-clean"}
        )
        assert calib_clean.status_code == 200
        assert calib_clean.json()["classification"] == "ROUTINE_NORMAL"

        calib_attack = client.post(
            "/api/llm/calibrate-journey",
            json={"user_id": "multi_user", "session_id": "sess-attack"}
        )
        assert calib_attack.status_code == 200
        assert calib_attack.json()["classification"] == "ADVERSARIAL_DRIFT"
        assert calib_attack.json()["case_category"] == "CASE_4_DIFF_DEVICE_DIFF_IP"

        # Restore default scenarios
        client.post("/api/scenarios/all/load")
