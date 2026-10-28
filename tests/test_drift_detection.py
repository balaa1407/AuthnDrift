"""
Unit tests for AuthDrift Assurance Drift Detection Engine (Objective 3).
"""

from datetime import datetime, timezone, timedelta
import pytest
from backend.models.event import AuthenticationEvent
from backend.models.detection import DriftResult
from backend.models.assurance import AssuranceLevel
from backend.detection.drift_detector import DriftDetector
from backend.detection.detection_rules import (
    RULE_FAILED_STRONG_SUCCESS_WEAK,
    RULE_MULTI_FAILURE_FALLBACK,
    RULE_DOWNGRADE_GENERAL,
    RULE_REPEATED_FAILURES_SAME_METHOD
)


def create_event(
    method: str,
    outcome: str = "SUCCESS",
    delta_seconds: int = 0,
    user_id: str = "user-101",
    event_type: str = "LOGIN"
) -> AuthenticationEvent:
    base_time = datetime(2026, 10, 30, 12, 0, 0, tzinfo=timezone.utc)
    return AuthenticationEvent(
        event_id=f"evt-{method}-{delta_seconds}",
        user_id=user_id,
        timestamp=base_time + timedelta(seconds=delta_seconds),
        event_type=event_type,
        authentication_method=method,
        outcome=outcome
    )


class TestDriftDetector:
    def setup_method(self):
        self.detector = DriftDetector()

    def test_empty_or_single_event_journey(self):
        assert self.detector.detect_drift([]).drift_detected is False
        assert self.detector.detect_drift([create_event("passkey")]).drift_detected is False

    def test_strong_auth_success_no_drift(self):
        journey = [
            create_event("passkey", "SUCCESS", 0),
            create_event("passkey", "SUCCESS", 10)
        ]
        res = self.detector.detect_drift(journey)
        assert res.drift_detected is False
        assert "No assurance decrease" in res.reason

    def test_failed_passkey_then_password_fallback(self):
        journey = [
            create_event("passkey", "FAILURE", 0),
            create_event("password", "SUCCESS", 15)
        ]
        res = self.detector.detect_drift(journey)
        assert res.drift_detected is True
        assert res.transition_type == RULE_FAILED_STRONG_SUCCESS_WEAK
        assert res.previous_method == "passkey"
        assert res.previous_assurance == AssuranceLevel.HIGH
        assert res.current_method == "password"
        assert res.current_assurance == AssuranceLevel.LOW
        assert "Failed strong authentication" in res.reason

    def test_multi_failure_then_fallback(self):
        journey = [
            create_event("passkey", "FAILURE", 0),
            create_event("totp", "FAILURE", 15),
            create_event("password", "SUCCESS", 30)
        ]
        res = self.detector.detect_drift(journey)
        assert res.drift_detected is True
        assert res.transition_type == RULE_MULTI_FAILURE_FALLBACK
        assert "Multiple failed authentication attempts" in res.reason

    def test_step_up_authentication_no_drift(self):
        # Step-up is desirable and legitimate: password first, then stepped-up to passkey
        journey = [
            create_event("password", "SUCCESS", 0),
            create_event("passkey", "SUCCESS", 20)
        ]
        res = self.detector.detect_drift(journey)
        assert res.drift_detected is False

    def test_repeated_failures_same_assurance(self):
        journey = [
            create_event("password", "FAILURE", 0),
            create_event("password", "FAILURE", 5),
            create_event("password", "FAILURE", 10)
        ]
        res = self.detector.detect_drift(journey)
        assert res.drift_detected is False
        assert res.transition_type == RULE_REPEATED_FAILURES_SAME_METHOD

    def test_general_downgrade_without_failure(self):
        journey = [
            create_event("passkey", "SUCCESS", 0),
            create_event("password", "SUCCESS", 25)
        ]
        res = self.detector.detect_drift(journey)
        assert res.drift_detected is True
        assert res.transition_type == RULE_DOWNGRADE_GENERAL
