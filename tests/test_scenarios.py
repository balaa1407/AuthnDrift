"""
Controlled Test Scenarios (TC01 to TC10) for AuthDrift Core Security Engine.
Validates end-to-end detection, contextual correlation, risk assessment, and explainable alerts.
"""

from datetime import datetime, timezone, timedelta
import pytest
from backend.models.event import AuthenticationEvent
from backend.models.detection import RiskSeverity
from backend.models.assurance import AssuranceLevel
from backend.engine import AuthDriftEngine
from backend.detection.detection_rules import (
    RULE_FAILED_STRONG_SUCCESS_WEAK,
    RULE_REPEATED_FAILURES_SAME_METHOD
)


def make_event(
    user_id: str,
    method: str,
    outcome: str = "SUCCESS",
    device_id: str = None,
    location: str = None,
    authenticator_id: str = None,
    event_type: str = "LOGIN",
    delta_seconds: int = 0
) -> AuthenticationEvent:
    base = datetime(2026, 10, 30, 14, 0, 0, tzinfo=timezone.utc)
    return AuthenticationEvent(
        event_id=f"evt-{user_id}-{delta_seconds}",
        user_id=user_id,
        timestamp=base + timedelta(seconds=delta_seconds),
        event_type=event_type,
        authentication_method=method,
        outcome=outcome,
        device_id=device_id,
        location=location,
        authenticator_id=authenticator_id
    )


class TestControlledScenarios:
    def setup_method(self):
        self.engine = AuthDriftEngine()
        self.known_devices = {"corporate-macbook-01", "pixel-9-pro"}
        self.known_locations = {"Bangalore, IN"}

    def test_tc01_known_device_passkey_success(self):
        """
        TC01: Known-device passkey success.
        Expected: High assurance assigned; no drift detected.
        """
        journey = [
            make_event("alice", "passkey", "SUCCESS", device_id="corporate-macbook-01", location="Bangalore, IN")
        ]
        alert = self.engine.evaluate_journey(
            journey,
            known_devices=self.known_devices,
            known_locations=self.known_locations
        )
        assert alert.drift_detected is False
        assert alert.risk_assessment.severity == RiskSeverity.LOW
        assert alert.risk_assessment.score == 0
        assert "No assurance degradation detected" in alert.explanation

    def test_tc02_failed_passkey_then_password_fallback(self):
        """
        TC02: Failed passkey followed by successful password fallback.
        Expected: Lower-assurance transition identified; drift flagged (HIGH -> LOW).
        """
        journey = [
            make_event("bob", "passkey", "FAILURE", delta_seconds=0),
            make_event("bob", "password", "SUCCESS", delta_seconds=15)
        ]
        alert = self.engine.evaluate_journey(journey)
        assert alert.drift_detected is True
        assert alert.drift_result.transition_type == RULE_FAILED_STRONG_SUCCESS_WEAK
        assert alert.drift_result.previous_assurance == AssuranceLevel.HIGH
        assert alert.drift_result.current_assurance == AssuranceLevel.LOW
        assert alert.risk_assessment.score >= 40

    def test_tc03_failed_passkey_password_success_new_device(self):
        """
        TC03: Failed passkey followed by password success from a new device.
        Expected: Drift and additional contextual signal identified, elevated risk.
        """
        journey = [
            make_event("carol", "passkey", "FAILURE", device_id="unfamiliar-phone-99", delta_seconds=0),
            make_event("carol", "password", "SUCCESS", device_id="unfamiliar-phone-99", delta_seconds=20)
        ]
        alert = self.engine.evaluate_journey(journey, known_devices=self.known_devices)
        assert alert.drift_detected is True
        assert alert.context_evidence.is_new_device is True
        assert alert.risk_assessment.score >= 70
        assert alert.risk_assessment.severity in [RiskSeverity.HIGH, RiskSeverity.CRITICAL]
        assert "new device" in alert.explanation.lower()

    def test_tc04_repeated_failed_authentication_attempts(self):
        """
        TC04: Repeated failed authentication attempts.
        Expected: Failure pattern evaluated according to documented rules.
        """
        journey = [
            make_event("dave", "password", "FAILURE", delta_seconds=0),
            make_event("dave", "password", "FAILURE", delta_seconds=5),
            make_event("dave", "password", "FAILURE", delta_seconds=10)
        ]
        alert = self.engine.evaluate_journey(journey)
        assert alert.drift_detected is False
        assert alert.drift_result.transition_type == RULE_REPEATED_FAILURES_SAME_METHOD
        assert alert.context_evidence.prior_failures_count == 3
        assert "Repeated Failures" in " ".join(alert.risk_assessment.triggered_factors)

    def test_tc05_downgrade_followed_by_authenticator_registration(self):
        """
        TC05: Authentication downgrade followed by authenticator registration.
        Expected: Registration event correlated when available, flagged as high-risk persistence.
        """
        journey = [
            make_event("eve", "passkey", "FAILURE", delta_seconds=0),
            make_event("eve", "password", "SUCCESS", delta_seconds=15),
            make_event(
                "eve",
                "webauthn",
                "SUCCESS",
                event_type="REGISTER_AUTHENTICATOR",
                authenticator_id="rogue-token-007",
                delta_seconds=30
            )
        ]
        alert = self.engine.evaluate_journey(journey)
        assert alert.drift_detected is True
        assert alert.context_evidence.authenticator_registered is True
        assert alert.risk_assessment.score >= 80
        assert alert.risk_assessment.severity == RiskSeverity.CRITICAL
        assert "authenticator credential was registered" in alert.explanation.lower()

    def test_tc06_legitimate_recovery_or_device_migration(self):
        """
        TC06: Legitimate recovery or device migration.
        Expected: Degradation identified without claiming certain attack; caveat included.
        """
        journey = [
            make_event("frank", "passkey", "FAILURE", delta_seconds=0),
            make_event("frank", "password", "SUCCESS", delta_seconds=15)
        ]
        alert = self.engine.evaluate_journey(journey)
        assert alert.drift_detected is True
        # Verify explanation contains the explicit caveat distinguishing downgrade from confirmed compromise
        assert "not definitive proof of an active compromise" in alert.explanation
        assert "legitimate factors" in alert.explanation.lower()

    def test_tc07_unknown_authentication_method(self):
        """
        TC07: Unknown authentication method.
        Expected: Graceful handling without fabricated assurance values (assigned LOW, fail-closed).
        """
        journey = [
            make_event("grace", "futuristic_quantum_handshake", "SUCCESS", delta_seconds=0),
            make_event("grace", "password", "SUCCESS", delta_seconds=20)
        ]
        alert = self.engine.evaluate_journey(journey)
        # Both unknown method and password map defensively to LOW, so no drift is falsely flagged
        assert alert.drift_detected is False
        assert alert.risk_assessment.severity == RiskSeverity.LOW

    def test_tc08_missing_device_or_location_information(self):
        """
        TC08: Missing device or location information.
        Expected: Detection continues using available evidence without inventing context.
        """
        journey = [
            make_event("heidi", "passkey", "FAILURE", device_id=None, location=None, delta_seconds=0),
            make_event("heidi", "password", "SUCCESS", device_id=None, location=None, delta_seconds=10)
        ]
        alert = self.engine.evaluate_journey(journey)
        assert alert.drift_detected is True
        assert alert.context_evidence.is_new_device is None
        assert alert.context_evidence.device_id is None
        assert alert.context_evidence.is_location_changed is None
        assert alert.context_evidence.location is None
        assert "device context unavailable" in " ".join(alert.context_evidence.evidence_notes).lower()

    def test_tc09_normal_journey_no_meaningful_downgrade(self):
        """
        TC09: Normal authentication journey with no meaningful downgrade.
        Expected: No false drift alert under the configured rules.
        """
        journey = [
            make_event("ivan", "totp", "SUCCESS", delta_seconds=0),
            make_event("ivan", "totp", "SUCCESS", delta_seconds=10)
        ]
        alert = self.engine.evaluate_journey(journey)
        assert alert.drift_detected is False
        assert alert.risk_assessment.score == 0
        assert alert.is_actionable is False

    def test_tc10_multiple_journeys_cross_user_isolation(self):
        """
        TC10: Multiple authentication journeys belonging to different users.
        Expected: No accidental cross-user correlation.
        """
        journey_alice = [make_event("alice", "passkey", "SUCCESS")]
        journey_bob = [make_event("bob", "password", "SUCCESS")]

        alert_alice = self.engine.evaluate_journey(journey_alice)
        alert_bob = self.engine.evaluate_journey(journey_bob)

        assert alert_alice.user_id == "alice"
        assert alert_bob.user_id == "bob"

        # Contaminated cross-user journey must be rejected
        cross_user_journey = [
            make_event("alice", "passkey", "FAILURE", delta_seconds=0),
            make_event("bob", "password", "SUCCESS", delta_seconds=10)
        ]
        with pytest.raises(ValueError, match="Cross-user journey contamination detected"):
            self.engine.evaluate_journey(cross_user_journey)
