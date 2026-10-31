"""
AuthDrift: Formal State-Machine Invariants & Property Tests.
Validates the mathematical state transitions and orthogonal dimensions:
1. Event Lifecycle Stage (AUTHENTICATION vs SESSION_LIFECYCLE vs ACCOUNT_LIFECYCLE)
2. Authentication Ceremony Outcome & Assurance Assignment Domain Restriction
3. Orthogonal Sequential Contextual & Telemetry Correlation
"""

from datetime import datetime, timezone, timedelta
import pytest

from backend.models.event import AuthenticationEvent, EventCategory
from backend.models.detection import RiskSeverity
from backend.models.assurance import AssuranceLevel
from backend.assurance.assurance_assignment import assign_event_assurance
from backend.detection.drift_detector import DriftDetector
from backend.detection.detection_rules import (
    DriftDetectionConfig,
    RULE_FAILED_STRONG_SUCCESS_WEAK,
    RULE_DOWNGRADE_GENERAL,
    RULE_REPEATED_FAILURES_SAME_METHOD,
    RULE_STEP_UP_AUTHENTICATION
)
from backend.correlation.context_analyzer import ContextAnalyzer
from backend.correlation.location_profiler import LocationProfiler
from backend.engine import AuthDriftEngine
from backend.normalization.keycloak import KeycloakEventNormalizer
from backend.normalization.okta import OktaEventNormalizer


BASE_TIME = datetime(2026, 10, 31, 10, 0, 0, tzinfo=timezone.utc)


def make_event(
    event_id: str,
    user_id: str = "alice",
    method: str = "passkey",
    outcome: str = "SUCCESS",
    category: str = EventCategory.AUTHENTICATION.value,
    event_type: str = "LOGIN",
    location: str = "Bengaluru, India",
    ip: str = "10.0.0.1",
    device: str = "device-01",
    delta_seconds: int = 0
) -> AuthenticationEvent:
    ev = AuthenticationEvent(
        event_id=event_id,
        user_id=user_id,
        timestamp=BASE_TIME + timedelta(seconds=delta_seconds),
        event_type=event_type,
        authentication_method=method,
        outcome=outcome,
        device_id=device,
        location=location,
        ip_address=ip,
        event_category=category
    )
    assign_event_assurance(ev)
    return ev


class TestStateMachineInvariants:
    def setup_method(self):
        self.engine = AuthDriftEngine()
        self.detector = DriftDetector()
        self.context_analyzer = ContextAnalyzer()

    def test_property_1_strong_success_refresh_token_diff_loc_weak_failure(self):
        """
        Property 1:
        e1: Strong SUCCESS (passkey, AUTHENTICATION, SUCCESS) at Loc1, IP1
        e2: REFRESH_TOKEN (refresh_token, SESSION_LIFECYCLE, SUCCESS) at Loc2, IP2
        e3: Weak FAILURE (password, AUTHENTICATION, FAILURE) at Loc2, IP2

        Invariants:
        - Assurance drift must NOT be detected (REFRESH_TOKEN is SESSION_LIFECYCLE, password failed).
        - Contextual anomalies emitted on refresh for LOCATION_CHANGE and IP_CHANGE.
        - Failed authentication recorded in failed_authentications.
        - Alert type is CONTEXTUAL_ANOMALY.
        """
        e1 = make_event("e1", "user-1", "passkey", "SUCCESS", EventCategory.AUTHENTICATION.value,
                        location="City A, Country A", ip="10.0.0.1", delta_seconds=0)
        e2 = make_event("e2", "user-1", "refresh_token", "SUCCESS", EventCategory.SESSION_LIFECYCLE.value,
                        event_type="REFRESH_TOKEN", location="City B, Country B", ip="198.51.100.1", delta_seconds=10)
        e3 = make_event("e3", "user-1", "password", "FAILURE", EventCategory.AUTHENTICATION.value,
                        event_type="LOGIN_ERROR", location="City B, Country B", ip="198.51.100.1", delta_seconds=20)

        journey = [e1, e2, e3]
        alert = self.engine.evaluate_journey(journey)

        # Invariant: No assurance drift
        assert alert.drift_detected is False
        assert alert.drift_result.drift_detected is False

        # Invariant: Contextual anomaly alert emitted
        assert alert.alert_type == "CONTEXTUAL_ANOMALY"

        # Invariant: Discrete telemetry deltas captured
        anomalies = alert.context_anomalies
        loc_anomalies = [a for a in anomalies if a.anomaly_type == "LOCATION_CHANGE"]
        ip_anomalies = [a for a in anomalies if a.anomaly_type == "IP_CHANGE"]

        assert len(loc_anomalies) >= 1
        assert loc_anomalies[0].source_event_id == "e1"
        assert loc_anomalies[0].target_event_id == "e2"
        assert loc_anomalies[0].previous_value == "City A, Country A"
        assert loc_anomalies[0].current_value == "City B, Country B"
        assert loc_anomalies[0].lifecycle_stage == EventCategory.SESSION_LIFECYCLE.value

        assert len(ip_anomalies) >= 1
        assert ip_anomalies[0].source_event_id == "e1"
        assert ip_anomalies[0].target_event_id == "e2"
        assert ip_anomalies[0].previous_value == "10.0.0.1"
        assert ip_anomalies[0].current_value == "198.51.100.1"

        # Invariant: Failed authentication recorded independently
        assert len(alert.failed_authentications) == 1
        assert alert.failed_authentications[0]["event_id"] == "e3"
        assert alert.failed_authentications[0]["authentication_method"] == "password"

    def test_property_2_strong_failure_weak_success(self):
        """
        Property 2:
        e1: Strong FAILURE (passkey, AUTHENTICATION, FAILURE)
        e2: Weak SUCCESS (password, AUTHENTICATION, SUCCESS)

        Invariants:
        - Assurance drift MUST be detected (Active Fallback Downgrade / Rule A).
        - Source (e1) and Target (e2) event IDs are explicitly cited.
        - Alert type is ASSURANCE_DRIFT.
        """
        e1 = make_event("e1", "user-2", "passkey", "FAILURE", event_type="LOGIN_ERROR", delta_seconds=0)
        e2 = make_event("e2", "user-2", "password", "SUCCESS", event_type="LOGIN", delta_seconds=15)

        journey = [e1, e2]
        alert = self.engine.evaluate_journey(journey)

        assert alert.drift_detected is True
        assert alert.drift_result.drift_detected is True
        assert alert.drift_result.transition_type == RULE_FAILED_STRONG_SUCCESS_WEAK
        assert alert.alert_type == "ASSURANCE_DRIFT"

        # Explicit source & target linkage
        assert alert.drift_result.source_event_id == "e1"
        assert alert.drift_result.target_event_id == "e2"
        assert alert.source_event_id == "e1"
        assert alert.target_event_id == "e2"

    def test_property_3_strong_failure_weak_failure(self):
        """
        Property 3:
        e1: Strong FAILURE (passkey, AUTHENTICATION, FAILURE)
        e2: Weak FAILURE (password, AUTHENTICATION, FAILURE)

        Invariants:
        - No drift detected (a failure cannot be the target of a downgrade).
        - Repeated failures recorded.
        - Both failures recorded in failed_authentications.
        """
        e1 = make_event("e1", "user-3", "passkey", "FAILURE", event_type="LOGIN_ERROR", delta_seconds=0)
        e2 = make_event("e2", "user-3", "password", "FAILURE", event_type="LOGIN_ERROR", delta_seconds=10)

        journey = [e1, e2]
        alert = self.engine.evaluate_journey(journey)

        assert alert.drift_detected is False
        assert alert.drift_result.drift_detected is False
        assert alert.drift_result.transition_type == RULE_REPEATED_FAILURES_SAME_METHOD

        assert len(alert.failed_authentications) == 2
        assert alert.failed_authentications[0]["event_id"] == "e1"
        assert alert.failed_authentications[1]["event_id"] == "e2"

    def test_property_4_strong_success_refresh_token_same_telemetry(self):
        """
        Property 4:
        e1: Strong SUCCESS (passkey, AUTHENTICATION, SUCCESS)
        e2: REFRESH_TOKEN (refresh_token, SESSION_LIFECYCLE, SUCCESS, same loc & IP)

        Invariants:
        - No drift detected.
        - No contextual anomalies.
        - Alert type is INFORMATIONAL.
        """
        e1 = make_event("e1", "user-4", "passkey", "SUCCESS", location="Bengaluru, India", ip="10.0.0.1", delta_seconds=0)
        e2 = make_event("e2", "user-4", "refresh_token", "SUCCESS", category=EventCategory.SESSION_LIFECYCLE.value,
                        event_type="REFRESH_TOKEN", location="Bengaluru, India", ip="10.0.0.1", delta_seconds=60)

        journey = [e1, e2]
        alert = self.engine.evaluate_journey(journey)

        assert alert.drift_detected is False
        assert alert.alert_type == "INFORMATIONAL"
        assert len(alert.context_anomalies) == 0
        assert len(alert.failed_authentications) == 0

    def test_property_5_standalone_refresh_token_location_change(self):
        """
        Property 5:
        User with established historical baseline has a journey containing a REFRESH_TOKEN
        from a new location.

        Invariants:
        - No assurance drift detected.
        - Contextual anomaly emitted for location change.
        - Alert type is CONTEXTUAL_ANOMALY.
        """
        profiler = LocationProfiler(min_successful_observations=2)
        history = [
            make_event("h1", "user-5", "passkey", "SUCCESS", location="Bengaluru, India", delta_seconds=-7200),
            make_event("h2", "user-5", "passkey", "SUCCESS", location="Bengaluru, India", delta_seconds=-3600),
        ]
        profiler.build_profiles(history)

        journey = [
            make_event("r1", "user-5", "refresh_token", "SUCCESS", category=EventCategory.SESSION_LIFECYCLE.value,
                       event_type="REFRESH_TOKEN", location="Berlin, Germany", ip="203.0.113.5", delta_seconds=0)
        ]
        alert = self.engine.evaluate_journey(journey, location_profiler=profiler)

        assert alert.drift_detected is False
        assert alert.alert_type == "CONTEXTUAL_ANOMALY"
        assert alert.context_evidence.location_status == "NEW"
        assert alert.context_evidence.location == "Berlin, Germany"
        assert alert.context_evidence.primary_location == "Bengaluru, India"
        assert len(alert.context_anomalies) >= 1
        assert alert.context_anomalies[0].anomaly_type == "LOCATION_CHANGE"
        assert alert.context_anomalies[0].current_value == "Berlin, Germany"

    def test_property_6_cross_ceremony_downgrade(self):
        """
        Property 6:
        e1: Strong SUCCESS (passkey, AUTHENTICATION, SUCCESS)
        e2: Weak SUCCESS (password, AUTHENTICATION, SUCCESS)

        Invariants:
        - Cross-ceremony downgrade (Rule B) detected.
        - e1 is source, e2 is target.
        """
        config = DriftDetectionConfig(detect_any_downgrade=True, require_prior_failure=False)
        detector = DriftDetector(config=config)

        e1 = make_event("e1", "user-6", "passkey", "SUCCESS", delta_seconds=0)
        e2 = make_event("e2", "user-6", "password", "SUCCESS", delta_seconds=60)

        result = detector.detect_drift([e1, e2])
        assert result.drift_detected is True
        assert result.transition_type == RULE_DOWNGRADE_GENERAL
        assert result.source_event_id == "e1"
        assert result.target_event_id == "e2"
        assert result.previous_assurance == AssuranceLevel.HIGH
        assert result.current_assurance == AssuranceLevel.LOW

    def test_property_7_step_up_authentication(self):
        """
        Property 7:
        e1: Weak SUCCESS (password, AUTHENTICATION, SUCCESS)
        e2: Strong SUCCESS (passkey, AUTHENTICATION, SUCCESS)

        Invariants:
        - No drift detected.
        - Transition recognized as RULE_STEP_UP_AUTHENTICATION.
        """
        e1 = make_event("e1", "user-7", "password", "SUCCESS", delta_seconds=0)
        e2 = make_event("e2", "user-7", "passkey", "SUCCESS", delta_seconds=30)

        result = self.detector.detect_drift([e1, e2])
        assert result.drift_detected is False
        assert result.transition_type == RULE_STEP_UP_AUTHENTICATION

    def test_property_8_normalizers_orthogonal_classification(self):
        """
        Property 8:
        Verify Keycloak and Okta normalizers accurately classify event categories
        and domain-restricted assurance levels.
        """
        kc_norm = KeycloakEventNormalizer()
        okta_norm = OktaEventNormalizer()

        # Keycloak LOGIN -> AUTHENTICATION, SUCCESS -> Effective HIGH
        kc_login = kc_norm.normalize_single({
            "id": "kc-1", "type": "LOGIN", "userId": "alice",
            "details": {"auth_method": "webauthn"}
        })
        assert kc_login.event_category == EventCategory.AUTHENTICATION.value
        assert kc_login.effective_assurance == AssuranceLevel.HIGH
        assert kc_login.attempted_assurance is None

        # Keycloak LOGIN_ERROR -> AUTHENTICATION, FAILURE -> Attempted HIGH, Effective None
        kc_fail = kc_norm.normalize_single({
            "id": "kc-2", "type": "LOGIN_ERROR", "userId": "alice",
            "details": {"auth_method": "webauthn", "error": "invalid"}
        })
        assert kc_fail.event_category == EventCategory.AUTHENTICATION.value
        assert kc_fail.effective_assurance is None
        assert kc_fail.attempted_assurance == AssuranceLevel.HIGH

        # Keycloak REFRESH_TOKEN -> SESSION_LIFECYCLE -> Effective None, Attempted None
        kc_refresh = kc_norm.normalize_single({
            "id": "kc-3", "type": "REFRESH_TOKEN", "userId": "alice",
            "details": {}
        })
        assert kc_refresh.event_category == EventCategory.SESSION_LIFECYCLE.value
        assert kc_refresh.effective_assurance is None
        assert kc_refresh.attempted_assurance is None

        # Okta user.session.refresh -> SESSION_LIFECYCLE -> Effective None
        okta_refresh = okta_norm.normalize_single({
            "uuid": "ok-1", "eventType": "user.session.refresh",
            "actor": {"id": "bob"},
            "outcome": {"result": "SUCCESS"}
        })
        assert okta_refresh.event_category == EventCategory.SESSION_LIFECYCLE.value
        assert okta_refresh.effective_assurance is None
        assert okta_refresh.attempted_assurance is None

