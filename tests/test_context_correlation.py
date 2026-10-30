"""
Unit tests for AuthDrift Contextual Correlation Engine (Objective 3).
"""

from datetime import datetime, timezone, timedelta
import pytest
from backend.models.event import AuthenticationEvent
from backend.correlation.context_analyzer import ContextAnalyzer


def make_context_event(
    user_id: str = "user-101",
    method: str = "password",
    outcome: str = "SUCCESS",
    device_id: str = None,
    location: str = None,
    authenticator_id: str = None,
    event_type: str = "LOGIN",
    delta_sec: int = 0
) -> AuthenticationEvent:
    base = datetime(2026, 10, 30, 10, 0, 0, tzinfo=timezone.utc)
    return AuthenticationEvent(
        event_id=f"evt-{delta_sec}",
        user_id=user_id,
        timestamp=base + timedelta(seconds=delta_sec),
        event_type=event_type,
        authentication_method=method,
        outcome=outcome,
        device_id=device_id,
        location=location,
        authenticator_id=authenticator_id
    )


class TestContextAnalyzer:
    def setup_method(self):
        self.analyzer = ContextAnalyzer()

    def test_new_device_detection(self):
        journey = [
            make_context_event(device_id="dev-unknown-999")
        ]
        evidence = self.analyzer.analyze_journey_context(
            journey,
            known_devices={"dev-laptop-001", "dev-phone-002"}
        )
        assert evidence.is_new_device is True
        assert evidence.device_id == "dev-unknown-999"

    def test_known_device_detection(self):
        journey = [
            make_context_event(device_id="dev-laptop-001")
        ]
        evidence = self.analyzer.analyze_journey_context(
            journey,
            known_devices={"dev-laptop-001"}
        )
        assert evidence.is_new_device is False

    def test_missing_device_and_location_no_fabrication(self):
        # When device/location is None, engine must NEVER invent values
        journey = [
            make_context_event(device_id=None, location=None)
        ]
        evidence = self.analyzer.analyze_journey_context(journey)
        assert evidence.is_new_device is None
        assert evidence.device_id is None
        assert evidence.is_location_changed is None
        assert evidence.location is None
        assert any("unavailable" in note.lower() for note in evidence.evidence_notes)

    def test_location_change_detection(self):
        journey = [
            make_context_event(location="Tokyo, JP")
        ]
        evidence = self.analyzer.analyze_journey_context(
            journey,
            known_locations={"New York, US", "London, UK"}
        )
        assert evidence.is_location_changed is True
        assert evidence.location == "Tokyo, JP"

    def test_authenticator_registration_event(self):
        journey = [
            make_context_event(method="password", outcome="SUCCESS", delta_sec=0),
            make_context_event(
                method="webauthn",
                outcome="SUCCESS",
                event_type="REGISTER_AUTHENTICATOR",
                authenticator_id="auth-key-555",
                delta_sec=30
            )
        ]
        evidence = self.analyzer.analyze_journey_context(journey)
        assert evidence.authenticator_registered is True
        assert evidence.authenticator_id == "auth-key-555"

    def test_cross_user_isolation_prevented(self):
        # Strictly verify no cross-user contamination
        journey = [
            make_context_event(user_id="alice"),
            make_context_event(user_id="bob")
        ]
        with pytest.raises(ValueError, match="Cross-user journey contamination detected"):
            self.analyzer.analyze_journey_context(journey)

    def test_failure_counting(self):
        journey = [
            make_context_event(outcome="FAILURE", delta_sec=0),
            make_context_event(outcome="FAILURE", delta_sec=5),
            make_context_event(outcome="SUCCESS", delta_sec=10)
        ]
        evidence = self.analyzer.analyze_journey_context(journey)
        assert evidence.prior_failures_count == 2

    def test_sticky_anomaly_new_device_multi_event(self):
        # Defect regression: unfamiliar device in early event must not be overwritten by known device in later event
        journey = [
            make_context_event(device_id="unfamiliar-phone-99", delta_sec=0),
            make_context_event(device_id="dev-laptop-001", delta_sec=10)
        ]
        evidence = self.analyzer.analyze_journey_context(
            journey,
            known_devices={"dev-laptop-001"}
        )
        assert evidence.is_new_device is True
        assert evidence.device_id == "unfamiliar-phone-99"

    def test_sticky_anomaly_location_change_multi_event(self):
        # Defect regression: unfamiliar location in early event must not be overwritten by known location in later event
        journey = [
            make_context_event(location="Tokyo, JP", delta_sec=0),
            make_context_event(location="New York, US", delta_sec=10)
        ]
        evidence = self.analyzer.analyze_journey_context(
            journey,
            known_locations={"New York, US"}
        )
        assert evidence.is_location_changed is True
        assert evidence.location == "Tokyo, JP"

    def test_device_observed_without_baseline_is_none(self):
        # Device observed but no baseline provided -> is_new_device should be None, not False
        journey = [
            make_context_event(device_id="my-phone", delta_sec=0)
        ]
        evidence = self.analyzer.analyze_journey_context(journey, known_devices=None)
        assert evidence.is_new_device is None
        assert evidence.device_id == "my-phone"
        assert any("no baseline available" in n.lower() for n in evidence.evidence_notes)

    def test_none_outcome_does_not_crash(self):
        # Null outcome handling
        journey = [
            make_context_event(outcome=None, delta_sec=0)
        ]
        evidence = self.analyzer.analyze_journey_context(journey)
        assert evidence.prior_failures_count == 0
