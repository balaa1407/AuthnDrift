"""
Unit tests for AuthDrift Assurance Drift Detection Engine (Objective 3).
Includes verification for all 6 canonical transition examples (A-F).
"""

from datetime import datetime, timezone, timedelta
from typing import Optional
import pytest
from backend.models.event import AuthenticationEvent
from backend.models.detection import DriftResult
from backend.models.assurance import AssuranceLevel
from backend.detection.drift_detector import DriftDetector
from backend.detection.detection_rules import (
    DriftDetectionConfig,
    RULE_FAILED_STRONG_SUCCESS_WEAK,
    RULE_MULTI_FAILURE_FALLBACK,
    RULE_DOWNGRADE_GENERAL,
    RULE_REPEATED_FAILURES_SAME_METHOD,
    RULE_STEP_UP_AUTHENTICATION
)


def create_event(
    method: str,
    outcome: Optional[str] = "SUCCESS",
    delta_seconds: int = 0,
    user_id: str = "user-101",
    event_type: str = "LOGIN",
    event_id: Optional[str] = None,
    timestamp: Optional[datetime] = None
) -> AuthenticationEvent:
    base_time = datetime(2026, 10, 30, 12, 0, 0, tzinfo=timezone.utc)
    evt_ts = timestamp if timestamp is not None else (base_time + timedelta(seconds=delta_seconds))
    return AuthenticationEvent(
        event_id=event_id or f"evt-{method}-{delta_seconds}",
        user_id=user_id,
        timestamp=evt_ts,
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

    def test_high_to_medium_downgrade(self):
        journey = [
            create_event("passkey", "FAILURE", 0),
            create_event("totp", "SUCCESS", 15)
        ]
        res = self.detector.detect_drift(journey)
        assert res.drift_detected is True
        assert res.transition_type == RULE_FAILED_STRONG_SUCCESS_WEAK
        assert res.previous_assurance == AssuranceLevel.HIGH
        assert res.current_assurance == AssuranceLevel.MEDIUM

    def test_medium_to_low_downgrade(self):
        journey = [
            create_event("totp", "FAILURE", 0),
            create_event("password", "SUCCESS", 15)
        ]
        res = self.detector.detect_drift(journey)
        assert res.drift_detected is True
        assert res.transition_type == RULE_FAILED_STRONG_SUCCESS_WEAK
        assert res.previous_assurance == AssuranceLevel.MEDIUM
        assert res.current_assurance == AssuranceLevel.LOW

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
        assert res.transition_type == RULE_STEP_UP_AUTHENTICATION

    def test_step_up_then_downgrade(self):
        # Journey steps up from password to passkey, but then subsequently downgrades back to password
        journey = [
            create_event("password", "SUCCESS", 0),
            create_event("passkey", "SUCCESS", 10),
            create_event("password", "SUCCESS", 20)
        ]
        res = self.detector.detect_drift(journey)
        assert res.drift_detected is True
        assert res.previous_method == "passkey"
        assert res.previous_assurance == AssuranceLevel.HIGH
        assert res.current_method == "password"
        assert res.current_assurance == AssuranceLevel.LOW
        assert res.transition_type == RULE_DOWNGRADE_GENERAL

    def test_weak_failure_then_strong_success_no_downgrade(self):
        # Failing a weak method and succeeding with a strong method is step-up recovery, NOT a downgrade
        journey = [
            create_event("password", "FAILURE", 0),
            create_event("passkey", "SUCCESS", 15)
        ]
        res = self.detector.detect_drift(journey)
        assert res.drift_detected is False
        assert res.transition_type == RULE_STEP_UP_AUTHENTICATION

    def test_strong_failure_then_weak_failure(self):
        # Failing strong method followed by failing weaker attempt without success
        # Repeated failures alone must not be labeled as assurance drift
        journey = [
            create_event("passkey", "FAILURE", 0),
            create_event("password", "FAILURE", 15)
        ]
        res = self.detector.detect_drift(journey)
        assert res.drift_detected is False
        assert res.transition_type == RULE_REPEATED_FAILURES_SAME_METHOD

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

    def test_unsorted_journey_events_defensive_sorting(self):
        # Defect regression: raw log aggregators might provide out-of-order events
        journey = [
            create_event("password", "SUCCESS", 20),
            create_event("passkey", "FAILURE", 0)
        ]
        res = self.detector.detect_drift(journey)
        assert res.drift_detected is True
        assert res.previous_method == "passkey"
        assert res.current_method == "password"

    def test_none_outcome_handling_does_not_crash(self):
        journey = [
            create_event("passkey", outcome=None, delta_seconds=0),
            create_event("password", outcome="SUCCESS", delta_seconds=10)
        ]
        res = self.detector.detect_drift(journey)
        # None outcome handled gracefully
        assert isinstance(res, DriftResult)

    def test_config_require_prior_failure(self):
        # When require_prior_failure is True, downgrade without failure is ignored
        config = DriftDetectionConfig(require_prior_failure=True)
        detector = DriftDetector(config=config)
        journey = [
            create_event("passkey", "SUCCESS", 0),
            create_event("password", "SUCCESS", 10)
        ]
        res = detector.detect_drift(journey)
        assert res.drift_detected is False

    def test_config_detect_any_downgrade_false(self):
        # When detect_any_downgrade is False, general downgrade without failure is ignored
        config = DriftDetectionConfig(detect_any_downgrade=False)
        detector = DriftDetector(config=config)
        journey = [
            create_event("passkey", "SUCCESS", 0),
            create_event("password", "SUCCESS", 10)
        ]
        res = detector.detect_drift(journey)
        assert res.drift_detected is False

    def test_config_min_assurance_drop_threshold(self):
        # min_assurance_drop=2: HIGH -> MEDIUM (drop 1) is ignored; HIGH -> LOW (drop 2) is flagged
        config = DriftDetectionConfig(min_assurance_drop=2)
        detector = DriftDetector(config=config)

        journey_drop_1 = [
            create_event("passkey", "FAILURE", 0),
            create_event("totp", "SUCCESS", 10)
        ]
        assert detector.detect_drift(journey_drop_1).drift_detected is False

        journey_drop_2 = [
            create_event("passkey", "FAILURE", 0),
            create_event("password", "SUCCESS", 10)
        ]
        assert detector.detect_drift(journey_drop_2).drift_detected is True

    def test_config_track_step_ups_false(self):
        # When track_step_ups is False, step-up yields NORMAL_JOURNEY
        config = DriftDetectionConfig(track_step_ups=False)
        detector = DriftDetector(config=config)
        journey = [
            create_event("password", "SUCCESS", 0),
            create_event("passkey", "SUCCESS", 10)
        ]
        res = detector.detect_drift(journey)
        assert res.drift_detected is False
        assert res.transition_type == "NORMAL_JOURNEY"

    def test_lifecycle_event_does_not_participate_in_drift(self):
        # REGISTER_AUTHENTICATOR must not be evaluated as an authentication downgrade
        journey = [
            create_event("passkey", "SUCCESS", 0),
            create_event("totp", "SUCCESS", 10, event_type="REGISTER_AUTHENTICATOR")
        ]
        res = self.detector.detect_drift(journey)
        # Only 1 true auth event exists, so insufficient auth events for drift
        assert res.drift_detected is False
        assert "Insufficient authentication events" in res.reason

    def test_duplicate_events_deduplication(self):
        # Repeated log delivery of identical event_id is safely deduplicated
        journey = [
            create_event("passkey", "FAILURE", 0, event_id="duplicate-event-01"),
            create_event("passkey", "FAILURE", 0, event_id="duplicate-event-01"),
            create_event("password", "SUCCESS", 10, event_id="event-02")
        ]
        res = self.detector.detect_drift(journey)
        assert res.drift_detected is True
        # Only 1 unique failure occurred before fallback
        assert res.transition_type == RULE_FAILED_STRONG_SUCCESS_WEAK


class TestCanonicalDriftExamples:
    """
    Validates the 6 canonical scenarios defined in the project specification:
    A. Strong fails, weaker succeeds -> Drift detected (HIGH -> LOW)
    B. Password succeeds, then stronger succeed -> No downgrade
    C. Repeated failures -> Repeated-failure signal, not assurance drift
    D. Strong methods fail, then strong method succeeds -> No weak-fallback drift
    E. Weak fails, stronger succeeds -> No downgrade (step-up)
    F. Strong fails, same-strength succeeds -> No assurance downgrade
    """
    def setup_method(self):
        self.detector = DriftDetector()

    def test_example_a_strong_fails_weaker_succeeds(self):
        """A: Passkey FAILURE -> Password SUCCESS -> Drift detected (HIGH -> LOW)"""
        journey = [
            create_event("passkey", "FAILURE", delta_seconds=0),
            create_event("password", "SUCCESS", delta_seconds=15)
        ]
        res = self.detector.detect_drift(journey)
        assert res.drift_detected is True
        assert res.previous_assurance == AssuranceLevel.HIGH
        assert res.current_assurance == AssuranceLevel.LOW
        assert res.transition_type == RULE_FAILED_STRONG_SUCCESS_WEAK

    def test_example_b_password_totp_passkey_all_success(self):
        """B: Password SUCCESS -> TOTP SUCCESS -> Passkey SUCCESS -> No downgrade"""
        journey = [
            create_event("password", "SUCCESS", delta_seconds=0),
            create_event("totp", "SUCCESS", delta_seconds=10),
            create_event("passkey", "SUCCESS", delta_seconds=20)
        ]
        res = self.detector.detect_drift(journey)
        assert res.drift_detected is False
        assert res.transition_type == RULE_STEP_UP_AUTHENTICATION

    def test_example_c_repeated_failures(self):
        """C: Password FAILURE -> Password FAILURE -> Password FAILURE -> Repeated failures, no drift"""
        journey = [
            create_event("password", "FAILURE", delta_seconds=0),
            create_event("password", "FAILURE", delta_seconds=5),
            create_event("password", "FAILURE", delta_seconds=10)
        ]
        res = self.detector.detect_drift(journey)
        assert res.drift_detected is False
        assert res.transition_type == RULE_REPEATED_FAILURES_SAME_METHOD

    def test_example_d_strong_fails_then_strong_succeeds(self):
        """D: Passkey FAILURE -> TOTP FAILURE -> Passkey SUCCESS -> No weak-fallback drift"""
        journey = [
            create_event("passkey", "FAILURE", delta_seconds=0),
            create_event("totp", "FAILURE", delta_seconds=10),
            create_event("passkey", "SUCCESS", delta_seconds=20)
        ]
        res = self.detector.detect_drift(journey)
        assert res.drift_detected is False

    def test_example_e_weak_fails_stronger_succeeds(self):
        """E: Password FAILURE -> Passkey SUCCESS -> No downgrade (step-up)"""
        journey = [
            create_event("password", "FAILURE", delta_seconds=0),
            create_event("passkey", "SUCCESS", delta_seconds=15)
        ]
        res = self.detector.detect_drift(journey)
        assert res.drift_detected is False
        assert res.transition_type == RULE_STEP_UP_AUTHENTICATION

    def test_example_f_strong_fails_same_strength_succeeds(self):
        """F: Passkey FAILURE -> Passkey SUCCESS -> No assurance downgrade"""
        journey = [
            create_event("passkey", "FAILURE", delta_seconds=0),
            create_event("passkey", "SUCCESS", delta_seconds=15)
        ]
        res = self.detector.detect_drift(journey)
        assert res.drift_detected is False
