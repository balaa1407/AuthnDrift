"""
AuthDrift: Comprehensive State-Machine Invariants, Event Classification,
Cross-Ceremony Rule B, and Context Anomaly Serialization Regression Tests.

Validates:
1. Event Classification (Keycloak & Okta):
   - Interactive authentication (LOGIN, LOGIN_ERROR, REGISTER, REGISTER_ERROR) -> AUTHENTICATION
   - Non-interactive session lifecycle (REFRESH_TOKEN, CODE_TO_TOKEN, user.session.refresh, app.oauth2.token.grant) -> SESSION_LIFECYCLE
   - Factor & credential management (REGISTER_AUTHENTICATOR, UPDATE_PASSWORD, UPDATE_TOTP, factor.enroll) -> ACCOUNT_LIFECYCLE
   - Unknown event types handled safely without fabricated assurance or credentials
   - Raw event payload caching and audit preservation
2. Cross-Ceremony Rule B:
   - Strong success -> weaker success (triggers Rule B)
   - Strong success -> stronger success (step-up, no drift)
   - Strong failure -> weaker success (triggers Rule A)
   - Strong success -> refresh event -> weaker success (Rule B triggers, refresh ignored)
   - Rule B disabled (require_prior_failure=True): strong success -> weaker success produces no drift
   - Deduplication / No duplicate alert for the same source-target pair
   - Source & target event IDs and explicit rule name cited
3. Context Anomaly Pipeline & Reproduction Scenario:
   - Reproduction test: WebAuthn LOGIN success -> REFRESH_TOKEN from different loc/IP -> LOGIN_ERROR password
     * No assurance drift
     * Location & IP anomalies captured on refresh event with lifecycle_stage="SESSION_LIFECYCLE"
     * Failed password recorded separately in failed_authentications
     * Refresh event has no effective/attempted assurance
   - Positive control: Passkey failure -> Password success triggers Rule A
   - Pipeline serialization to_dict() preserves all ContextAnomaly fields
"""

from datetime import datetime, timezone, timedelta
from typing import Any, Dict
import pytest

from backend.models.event import AuthenticationEvent, EventCategory
from backend.models.detection import RiskSeverity, ContextAnomaly
from backend.models.assurance import AssuranceLevel
from backend.assurance.assurance_assignment import assign_event_assurance
from backend.detection.drift_detector import DriftDetector
from backend.detection.detection_rules import (
    DriftDetectionConfig,
    RULE_CROSS_CEREMONY_DOWNGRADE,
    RULE_DOWNGRADE_GENERAL,
    RULE_FAILED_STRONG_SUCCESS_WEAK,
    RULE_MULTI_FAILURE_FALLBACK,
    RULE_REPEATED_FAILURES_SAME_METHOD,
    RULE_STEP_UP_AUTHENTICATION
)
from backend.correlation.context_analyzer import ContextAnalyzer
from backend.correlation.location_profiler import LocationProfiler
from backend.engine import AuthDriftEngine
from backend.normalization.keycloak import KeycloakEventNormalizer
from backend.normalization.okta import OktaEventNormalizer
from backend.pipeline.pipeline import AuthDriftPipeline


BASE_TIME = datetime(2026, 10, 31, 12, 0, 0, tzinfo=timezone.utc)


def make_test_event(
    event_id: str,
    user_id: str = "alice",
    method: str = "passkey",
    outcome: str = "SUCCESS",
    category: str = EventCategory.AUTHENTICATION.value,
    event_type: str = "LOGIN",
    location: str = "Bengaluru, India",
    ip: str = "192.168.1.1",
    device: str = "laptop-01",
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


class TestEventClassification:
    """Requirement 1: Keycloak & Okta Event Classification and Assurance Domain Restriction."""

    def setup_method(self):
        self.kc_norm = KeycloakEventNormalizer()
        self.okta_norm = OktaEventNormalizer()

    def test_keycloak_interactive_authentication(self):
        # LOGIN success
        ev_login = self.kc_norm.normalize_single({
            "id": "kc-login-1", "type": "LOGIN", "userId": "u1",
            "details": {"username": "user1", "auth_method": "webauthn"}
        })
        assert ev_login.event_category == EventCategory.AUTHENTICATION.value
        assert ev_login.outcome == "SUCCESS"
        assert ev_login.effective_assurance == AssuranceLevel.HIGH
        assert ev_login.attempted_assurance is None
        assert ev_login.authentication_method == "passkey"

        # LOGIN failure
        ev_login_err = self.kc_norm.normalize_single({
            "id": "kc-login-2", "type": "LOGIN_ERROR", "userId": "u1",
            "details": {"username": "user1", "auth_method": "password", "error": "invalid"}
        })
        assert ev_login_err.event_category == EventCategory.AUTHENTICATION.value
        assert ev_login_err.outcome == "FAILURE"
        assert ev_login_err.effective_assurance is None
        assert ev_login_err.attempted_assurance == AssuranceLevel.LOW

        # User self-registration (interactive authentication ceremony)
        ev_reg = self.kc_norm.normalize_single({
            "id": "kc-reg-1", "type": "REGISTER", "userId": "u1",
            "details": {"username": "new_user", "auth_method": "password"}
        })
        assert ev_reg.event_category == EventCategory.AUTHENTICATION.value
        assert ev_reg.outcome == "SUCCESS"
        assert ev_reg.effective_assurance == AssuranceLevel.LOW

    def test_keycloak_session_lifecycle(self):
        # REFRESH_TOKEN
        ev_ref = self.kc_norm.normalize_single({
            "id": "kc-ref-1", "type": "REFRESH_TOKEN", "userId": "u1",
            "details": {"username": "user1"}
        })
        assert ev_ref.event_category == EventCategory.SESSION_LIFECYCLE.value
        assert ev_ref.effective_assurance is None
        assert ev_ref.attempted_assurance is None
        assert ev_ref.authentication_method == "refresh_token"

        # CODE_TO_TOKEN
        ev_code = self.kc_norm.normalize_single({
            "id": "kc-code-1", "type": "CODE_TO_TOKEN", "userId": "u1",
            "details": {"username": "user1"}
        })
        assert ev_code.event_category == EventCategory.SESSION_LIFECYCLE.value
        assert ev_code.effective_assurance is None
        assert ev_code.attempted_assurance is None

        # LOGOUT
        ev_logout = self.kc_norm.normalize_single({
            "id": "kc-out-1", "type": "LOGOUT", "userId": "u1",
            "details": {"username": "user1"}
        })
        assert ev_logout.event_category == EventCategory.SESSION_LIFECYCLE.value

    def test_keycloak_account_lifecycle(self):
        # Factor registration
        ev_reg_auth = self.kc_norm.normalize_single({
            "id": "kc-fac-1", "type": "REGISTER_AUTHENTICATOR", "userId": "u1",
            "details": {"username": "user1", "auth_method": "webauthn"}
        })
        assert ev_reg_auth.event_category == EventCategory.ACCOUNT_LIFECYCLE.value
        assert ev_reg_auth.effective_assurance is None
        assert ev_reg_auth.attempted_assurance is None

        # Password update
        ev_pwd = self.kc_norm.normalize_single({
            "id": "kc-pwd-1", "type": "UPDATE_PASSWORD", "userId": "u1",
            "details": {"username": "user1"}
        })
        assert ev_pwd.event_category == EventCategory.ACCOUNT_LIFECYCLE.value
        assert ev_pwd.effective_assurance is None

        # TOTP update
        ev_totp = self.kc_norm.normalize_single({
            "id": "kc-totp-1", "type": "UPDATE_TOTP", "userId": "u1",
            "details": {"username": "user1"}
        })
        assert ev_totp.event_category == EventCategory.ACCOUNT_LIFECYCLE.value

    def test_okta_classification(self):
        # Interactive authentication
        ev_auth = self.okta_norm.normalize_single({
            "uuid": "okta-auth-1",
            "eventType": "user.authentication.authenticate",
            "outcome": {"result": "SUCCESS"},
            "actor": {"alternateId": "bob@corp.com"},
            "authenticationContext": {"credentialProvider": "FIDO2 (WebAuthn)"}
        })
        assert ev_auth.event_category == EventCategory.AUTHENTICATION.value
        assert ev_auth.effective_assurance == AssuranceLevel.HIGH
        assert ev_auth.outcome == "SUCCESS"

        # Session refresh
        ev_ref = self.okta_norm.normalize_single({
            "uuid": "okta-ref-1",
            "eventType": "user.session.refresh",
            "outcome": {"result": "SUCCESS"},
            "actor": {"alternateId": "bob@corp.com"}
        })
        assert ev_ref.event_category == EventCategory.SESSION_LIFECYCLE.value
        assert ev_ref.effective_assurance is None
        assert ev_ref.attempted_assurance is None

        # Token grant
        ev_token = self.okta_norm.normalize_single({
            "uuid": "okta-tok-1",
            "eventType": "app.oauth2.token.grant.refresh_token",
            "outcome": {"result": "SUCCESS"},
            "actor": {"alternateId": "bob@corp.com"}
        })
        assert ev_token.event_category == EventCategory.SESSION_LIFECYCLE.value
        assert ev_token.effective_assurance is None

        # Factor enrollment
        ev_factor = self.okta_norm.normalize_single({
            "uuid": "okta-fac-1",
            "eventType": "user.mfa.factor.activate",
            "outcome": {"result": "SUCCESS"},
            "actor": {"alternateId": "bob@corp.com"}
        })
        assert ev_factor.event_category == EventCategory.ACCOUNT_LIFECYCLE.value
        assert ev_factor.effective_assurance is None

    def test_unknown_event_types_safe_no_fabricated_assurance(self):
        # Unknown Keycloak event type without auth_method
        raw_unknown = {
            "id": "kc-unknown-99",
            "type": "CUSTOM_ORG_AUDIT_LOG",
            "userId": "usr-unknown-1",
            "details": {"action": "export_data"}
        }
        ev_kc = self.kc_norm.normalize_single(raw_unknown)
        assert ev_kc is not None
        assert ev_kc.authentication_method is None
        assert ev_kc.effective_assurance is None
        assert ev_kc.attempted_assurance is None

        # Raw event is preserved in debug cache for audit
        cached = self.kc_norm.get_raw_event("kc-unknown-99")
        assert cached == raw_unknown

        # Unknown Okta event type without auth_method
        raw_okta = {
            "uuid": "okta-unknown-99",
            "eventType": "system.org.rate_limit.warning",
            "outcome": {"result": "SUCCESS"},
            "actor": {"alternateId": "sysadmin@corp.com"}
        }
        ev_okta = self.okta_norm.normalize_single(raw_okta)
        assert ev_okta is not None
        assert ev_okta.authentication_method is None
        assert ev_okta.effective_assurance is None
        assert ev_okta.attempted_assurance is None


class TestCrossCeremonyRuleB:
    """Requirement 2: Validate and clarify cross-ceremony Rule B."""

    def setup_method(self):
        # Rule B is enabled by default in DriftDetectionConfig
        self.default_detector = DriftDetector()
        self.rule_b_disabled_detector = DriftDetector(
            config=DriftDetectionConfig(require_prior_failure=True)
        )

    def test_strong_success_then_weaker_success_triggers_rule_b(self):
        """Strong success -> weaker success triggers Rule B."""
        e1 = make_test_event("e1", "user-b1", "passkey", "SUCCESS", delta_seconds=0)
        e2 = make_test_event("e2", "user-b1", "password", "SUCCESS", delta_seconds=60)

        res = self.default_detector.detect_drift([e1, e2])
        assert res.drift_detected is True
        assert res.transition_type in [RULE_CROSS_CEREMONY_DOWNGRADE, RULE_DOWNGRADE_GENERAL]
        assert res.source_event_id == "e1"
        assert res.target_event_id == "e2"
        assert res.previous_assurance == AssuranceLevel.HIGH
        assert res.current_assurance == AssuranceLevel.LOW
        assert "Rule B" in res.reason

    def test_strong_success_then_stronger_success_step_up_no_drift(self):
        """Strong success -> stronger success (or same) does not trigger drift."""
        e1 = make_test_event("e1", "user-b2", "totp", "SUCCESS", delta_seconds=0)
        e2 = make_test_event("e2", "user-b2", "passkey", "SUCCESS", delta_seconds=30)

        res = self.default_detector.detect_drift([e1, e2])
        assert res.drift_detected is False
        assert res.transition_type == RULE_STEP_UP_AUTHENTICATION

    def test_strong_failure_then_weaker_success_triggers_rule_a(self):
        """Strong failure -> weaker success triggers Rule A, not Rule B."""
        e1 = make_test_event("e1", "user-b3", "passkey", "FAILURE", event_type="LOGIN_ERROR", delta_seconds=0)
        e2 = make_test_event("e2", "user-b3", "password", "SUCCESS", delta_seconds=15)

        res = self.default_detector.detect_drift([e1, e2])
        assert res.drift_detected is True
        assert res.transition_type == RULE_FAILED_STRONG_SUCCESS_WEAK
        assert res.source_event_id == "e1"
        assert res.target_event_id == "e2"

    def test_strong_success_then_refresh_then_weaker_success(self):
        """Strong success -> refresh event -> weaker success triggers Rule B across the two authentications."""
        e1 = make_test_event("e1", "user-b4", "passkey", "SUCCESS", delta_seconds=0)
        e2 = make_test_event("e2", "user-b4", "refresh_token", "SUCCESS",
                             category=EventCategory.SESSION_LIFECYCLE.value,
                             event_type="REFRESH_TOKEN", delta_seconds=30)
        e3 = make_test_event("e3", "user-b4", "password", "SUCCESS", delta_seconds=60)

        res = self.default_detector.detect_drift([e1, e2, e3])
        assert res.drift_detected is True
        assert res.transition_type in [RULE_CROSS_CEREMONY_DOWNGRADE, RULE_DOWNGRADE_GENERAL]
        assert res.source_event_id == "e1"
        assert res.target_event_id == "e3"

    def test_rule_b_disabled_suppresses_cross_ceremony_downgrade(self):
        """When require_prior_failure=True, Rule B is disabled."""
        e1 = make_test_event("e1", "user-b5", "passkey", "SUCCESS", delta_seconds=0)
        e2 = make_test_event("e2", "user-b5", "password", "SUCCESS", delta_seconds=60)

        res = self.rule_b_disabled_detector.detect_drift([e1, e2])
        assert res.drift_detected is False
        assert res.transition_type == "NORMAL_JOURNEY"

    def test_no_duplicate_alert_for_same_source_target_pair(self):
        """Rule A and Rule B do not emit duplicate alerts for the same source-target pair."""
        # Scenario: passkey fails, password succeeds.
        e1 = make_test_event("e1", "user-b6", "passkey", "FAILURE", event_type="LOGIN_ERROR", delta_seconds=0)
        e2 = make_test_event("e2", "user-b6", "password", "SUCCESS", delta_seconds=10)

        engine = AuthDriftEngine()
        alert = engine.evaluate_journey([e1, e2])

        assert alert.drift_detected is True
        assert alert.drift_result.transition_type == RULE_FAILED_STRONG_SUCCESS_WEAK
        assert alert.source_event_id == "e1"
        assert alert.target_event_id == "e2"


class TestReproductionScenarioAndContextPipeline:
    """Requirement 3 & 4: Full Pipeline Reproduction Test and Structured Anomaly Tracing."""

    def setup_method(self):
        self.engine = AuthDriftEngine()
        self.pipeline = AuthDriftPipeline()

    def test_bengaluru_frankfurt_refresh_failed_password_reproduction(self):
        """
        Required Reproduction Test:
        - WebAuthn LOGIN success (Bengaluru, IP1)
        - REFRESH_TOKEN (Frankfurt, IP2)
        - LOGIN_ERROR password (Frankfurt, IP2)

        Must satisfy:
        1. No assurance drift detected (REFRESH_TOKEN is SESSION_LIFECYCLE, password failed).
        2. Location and IP changes appear as contextual anomalies on the refresh event.
        3. The failed password attempt is recorded separately in failed_authentications.
        4. The refresh event has no effective assurance value.
        """
        e1 = make_test_event(
            event_id="evt-blr-01",
            user_id="repro_user",
            method="passkey",
            outcome="SUCCESS",
            category=EventCategory.AUTHENTICATION.value,
            event_type="LOGIN",
            location="Bengaluru, India",
            ip="203.0.113.10",
            delta_seconds=0
        )

        e2 = make_test_event(
            event_id="evt-fra-02",
            user_id="repro_user",
            method="refresh_token",
            outcome="SUCCESS",
            category=EventCategory.SESSION_LIFECYCLE.value,
            event_type="REFRESH_TOKEN",
            location="Frankfurt, Germany",
            ip="198.51.100.25",
            delta_seconds=300
        )

        e3 = make_test_event(
            event_id="evt-fra-03",
            user_id="repro_user",
            method="password",
            outcome="FAILURE",
            category=EventCategory.AUTHENTICATION.value,
            event_type="LOGIN_ERROR",
            location="Frankfurt, Germany",
            ip="198.51.100.25",
            delta_seconds=360
        )

        # 4. Refresh event must have no assurance assigned
        assert e2.effective_assurance is None
        assert e2.attempted_assurance is None

        journey = [e1, e2, e3]
        alert = self.engine.evaluate_journey(journey)

        # 1. No assurance drift
        assert alert.drift_detected is False
        assert alert.drift_result.drift_detected is False
        assert alert.alert_type == "CONTEXTUAL_ANOMALY"

        # 2. Location and IP changes appear as contextual anomalies
        anomalies = alert.context_anomalies
        loc_anomalies = [a for a in anomalies if a.anomaly_type == "LOCATION_CHANGE"]
        ip_anomalies = [a for a in anomalies if a.anomaly_type == "IP_CHANGE"]

        assert len(loc_anomalies) >= 1
        assert loc_anomalies[0].source_event_id == "evt-blr-01"
        assert loc_anomalies[0].target_event_id == "evt-fra-02"
        assert loc_anomalies[0].previous_value == "Bengaluru, India"
        assert loc_anomalies[0].current_value == "Frankfurt, Germany"
        assert loc_anomalies[0].lifecycle_stage == EventCategory.SESSION_LIFECYCLE.value

        assert len(ip_anomalies) >= 1
        assert ip_anomalies[0].source_event_id == "evt-blr-01"
        assert ip_anomalies[0].target_event_id == "evt-fra-02"
        assert ip_anomalies[0].previous_value == "203.0.113.10"
        assert ip_anomalies[0].current_value == "198.51.100.25"
        assert ip_anomalies[0].lifecycle_stage == EventCategory.SESSION_LIFECYCLE.value

        # 3. Failed password attempt is shown separately in failed_authentications
        assert len(alert.failed_authentications) == 1
        failed = alert.failed_authentications[0]
        assert failed["event_id"] == "evt-fra-03"
        assert failed["authentication_method"] == "password"
        assert failed["location"] == "Frankfurt, Germany"
        assert failed["ip_address"] == "198.51.100.25"

    def test_positive_control_passkey_failure_password_success(self):
        """Positive Control: Passkey LOGIN_ERROR -> password LOGIN success triggers Rule A."""
        e1 = make_test_event(
            event_id="pos-ctrl-01",
            user_id="pos_user",
            method="passkey",
            outcome="FAILURE",
            event_type="LOGIN_ERROR",
            delta_seconds=0
        )
        e2 = make_test_event(
            event_id="pos-ctrl-02",
            user_id="pos_user",
            method="password",
            outcome="SUCCESS",
            event_type="LOGIN",
            delta_seconds=15
        )

        alert = self.engine.evaluate_journey([e1, e2])

        assert alert.drift_detected is True
        assert alert.drift_result.drift_detected is True
        assert alert.drift_result.transition_type == RULE_FAILED_STRONG_SUCCESS_WEAK
        assert alert.source_event_id == "pos-ctrl-01"
        assert alert.target_event_id == "pos-ctrl-02"
        assert alert.alert_type == "ASSURANCE_DRIFT"

    def test_pipeline_serialization_preserves_anomalies_and_events(self):
        """Ensure pipeline serialization to_dict() preserves structured anomaly fields."""
        raw_events = [
            {
                "id": "e-pipe-1",
                "time": 1730300000000,
                "type": "LOGIN",
                "ipAddress": "10.0.0.1",
                "details": {
                    "username": "charlie",
                    "auth_method": "webauthn",
                    "location": "London, UK",
                    "device_id": "laptop-01"
                }
            },
            {
                "id": "e-pipe-2",
                "time": 1730300060000,
                "type": "REFRESH_TOKEN",
                "ipAddress": "198.51.100.5",
                "details": {
                    "username": "charlie",
                    "location": "Paris, France"
                }
            }
        ]

        result = self.pipeline.process_raw_events(raw_events, provider="keycloak")
        payload = result.to_dict()

        assert "alerts" in payload
        assert len(payload["alerts"]) == 1
        alert_dict = payload["alerts"][0]

        # Verify context anomalies structure in alert dict
        assert "context_anomalies" in alert_dict
        anoms = alert_dict["context_anomalies"]
        assert len(anoms) >= 1

        loc_anom = next(a for a in anoms if a["anomaly_type"] == "LOCATION_CHANGE")
        assert loc_anom["source_event_id"] == "e-pipe-1"
        assert loc_anom["target_event_id"] == "e-pipe-2"
        assert loc_anom["previous_value"] == "London, UK"
        assert loc_anom["current_value"] == "Paris, France"
        assert loc_anom["lifecycle_stage"] == EventCategory.SESSION_LIFECYCLE.value

        ip_anom = next(a for a in anoms if a["anomaly_type"] == "IP_CHANGE")
        assert ip_anom["source_event_id"] == "e-pipe-1"
        assert ip_anom["target_event_id"] == "e-pipe-2"
        assert ip_anom["previous_value"] == "10.0.0.1"
        assert ip_anom["current_value"] == "198.51.100.5"

        # Verify journey dictionary also preserves context_anomalies
        assert "journeys" in payload
        assert len(payload["journeys"]) == 1
        assert "context_anomalies" in payload["journeys"][0]
        assert len(payload["journeys"][0]["context_anomalies"]) >= 1

