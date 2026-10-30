"""
AuthDrift End-to-End Pipeline Integration Tests.
Validates:
- Complete flow: Raw Keycloak logs -> Normalization -> Journey Reconstruction -> Balaa's AuthDriftEngine
- Verifies real SecurityAlert generation with actual risk scores and explainable rationale
"""

import pytest
from backend.pipeline.pipeline import AuthDriftPipeline
from backend.models.detection import RiskSeverity
from keycloak.generate_keycloak_fixtures import generate_keycloak_fixtures


class TestPipelineE2E:
    def setup_method(self):
        self.pipeline = AuthDriftPipeline()

    def test_full_pipeline_controlled_scenarios(self):
        raw_events = generate_keycloak_fixtures()
        result = self.pipeline.process_raw_events(raw_events, provider="keycloak")

        # Basic pipeline assertions
        assert result.total_raw_events == len(raw_events)
        assert len(result.normalized_events) == len(raw_events)
        assert len(result.journeys) > 0
        assert len(result.alerts) == len(result.journeys)

        # Inspect specific journeys and alerts from Balaa's engine
        alert_map = {a.user_id: a for a in result.alerts}

        # Alice: TC01 - Passkey Success
        assert "alice" in alert_map
        alice_alert = alert_map["alice"]
        assert alice_alert.drift_detected is False
        assert alice_alert.risk_assessment.severity == RiskSeverity.LOW

        # Bob: TC02 - Passkey Failure -> Password Fallback
        assert "bob" in alert_map
        bob_alert = alert_map["bob"]
        assert bob_alert.drift_detected is True
        assert bob_alert.drift_result.current_method == "password"
        assert bob_alert.drift_result.previous_method == "passkey"
        assert bob_alert.risk_assessment.score >= 40

        # Carol: TC03 - Passkey Failure -> Password Success on NEW Device
        assert "carol" in alert_map
        carol_alert = alert_map["carol"]
        assert carol_alert.drift_detected is True
        assert carol_alert.context_evidence.is_new_device is True
        assert carol_alert.risk_assessment.severity in [RiskSeverity.HIGH, RiskSeverity.CRITICAL]

        # Eve: TC05 - Downgrade followed by Authenticator Registration
        assert "eve" in alert_map
        eve_alert = alert_map["eve"]
        assert eve_alert.drift_detected is True
        assert eve_alert.context_evidence.authenticator_registered is True
        assert eve_alert.risk_assessment.severity == RiskSeverity.CRITICAL

    def test_pipeline_serialization_to_dict(self):
        raw_events = [
            {
                "id": "ser-01",
                "time": 1730300400000,
                "type": "LOGIN",
                "details": {"username": "test_user", "auth_method": "passkey"}
            }
        ]
        result = self.pipeline.process_raw_events(raw_events, provider="keycloak")
        d = result.to_dict()
        assert "total_raw_events" in d
        assert "metrics" in d
        assert "events" in d
        assert "journeys" in d
        assert "alerts" in d
        assert d["events"][0]["user_id"] == "test_user"

