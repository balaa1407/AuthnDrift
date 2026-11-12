"""
AuthDrift: Unit Tests for Refined Drift Classification Rules (Person 1 Task 2).
Verifies the exact 5 cases mandated by Person 1 requirements:
- Case 1: Same device, same IP -> Genuine recovery candidate (suppress drift alert).
- Case 2: Different device, same IP -> Drift alert (lateral movement on LAN).
- Case 3: Same device, different IP -> Drift alert (VPN/proxy routing).
- Case 4: Different device, different IP -> High-severity drift alert (credential theft).
- Case 5: Fallback followed by rogue authenticator registration -> Critical drift alert.
- Missing context invariant: device_id=None or ip_address=None MUST NOT be treated as a match.
"""

from datetime import datetime, timezone, timedelta
import pytest

from backend.pipeline.pipeline import AuthDriftPipeline
from backend.models.detection import RiskSeverity
from backend.models.event import AuthenticationEvent
from backend.correlation.context_analyzer import ContextAnalyzer


class TestRefinedDriftClassificationRules:
    """Rigorous verification of the 5 canonical drift/recovery cases and fail-closed invariants."""

    @pytest.fixture(autouse=True)
    def setup_pipeline(self):
        # Register a known user with known primary device and primary IP baseline
        self.user_id = "alice_analyst"
        self.primary_dev = "dev-macbook-alice"
        self.primary_ip = "192.168.1.100"
        self.primary_loc = "Bengaluru, India"

        self.pipeline = AuthDriftPipeline()
        self.pipeline.known_devices.add(self.primary_dev)
        self.pipeline.known_ips = {self.primary_ip}

    def test_case_1_same_device_same_ip_genuine_recovery(self):
        """
        Case 1: User fails passkey, falls back to password on SAME device and SAME IP.
        Expected:
        - Classified as genuine recovery candidate (is_recovery_candidate = True)
        - Drift alert suppressed (drift_detected = False, alert_type = 'INFORMATIONAL')
        - Risk score = 0, RiskSeverity = LOW
        """
        raw_events = [
            {
                "time": "2026-11-12T10:00:00Z",
                "type": "LOGIN_ERROR",
                "realmId": "master",
                "userId": self.user_id,
                "ipAddress": self.primary_ip,
                "details": {
                    "auth_method": "passkey",
                    "device_id": self.primary_dev,
                    "location": self.primary_loc,
                    "error": "user_cancelled"
                }
            },
            {
                "time": "2026-11-12T10:00:20Z",
                "type": "LOGIN",
                "realmId": "master",
                "userId": self.user_id,
                "ipAddress": self.primary_ip,
                "details": {
                    "auth_method": "password",
                    "device_id": self.primary_dev,
                    "location": self.primary_loc
                }
            }
        ]

        result = self.pipeline.process_raw_events(raw_events, provider="keycloak")
        assert len(result.alerts) == 1
        alert = result.alerts[0]

        # Invariants for Case 1
        assert alert.is_recovery_candidate is True
        assert alert.context_evidence.is_recovery_candidate is True
        assert alert.context_evidence.is_primary_device_matched is True
        assert alert.context_evidence.is_primary_ip_matched is True
        assert alert.case_category == "CASE_1_SAME_DEVICE_SAME_IP"
        assert alert.recovery_classification == "GENUINE_RECOVERY"

        # Suppressed alert invariants
        assert alert.drift_detected is False
        assert alert.alert_type == "INFORMATIONAL"
        assert alert.is_actionable is False
        assert alert.risk_assessment.score == 0
        assert alert.risk_assessment.severity == RiskSeverity.LOW

    def test_case_2_diff_device_same_ip_drift_alert(self):
        """
        Case 2: Passkey fails, password succeeds from DIFFERENT device on SAME IP (e.g., LAN lateral shift).
        Expected:
        - Classified as drift alert (drift_detected = True, alert_type = 'ASSURANCE_DRIFT')
        - is_recovery_candidate = False
        - case_category = 'CASE_2_DIFF_DEVICE_SAME_IP'
        - Elevated risk score (>= 70)
        """
        attacker_dev = "unfamiliar-linux-box"
        raw_events = [
            {
                "time": "2026-11-12T10:00:00Z",
                "type": "LOGIN_ERROR",
                "realmId": "master",
                "userId": self.user_id,
                "ipAddress": self.primary_ip,
                "details": {
                    "auth_method": "passkey",
                    "device_id": self.primary_dev,
                    "location": self.primary_loc,
                    "error": "fido2_timeout"
                }
            },
            {
                "time": "2026-11-12T10:00:30Z",
                "type": "LOGIN",
                "realmId": "master",
                "userId": self.user_id,
                "ipAddress": self.primary_ip,
                "details": {
                    "auth_method": "password",
                    "device_id": attacker_dev,
                    "location": self.primary_loc
                }
            }
        ]

        result = self.pipeline.process_raw_events(raw_events, provider="keycloak")
        assert len(result.alerts) == 1
        alert = result.alerts[0]

        assert alert.drift_detected is True
        assert alert.alert_type == "ASSURANCE_DRIFT"
        assert alert.is_recovery_candidate is False
        assert alert.context_evidence.is_primary_device_matched is False
        assert alert.context_evidence.is_primary_ip_matched is True
        assert alert.case_category == "CASE_2_DIFF_DEVICE_SAME_IP"
        assert alert.risk_assessment.score >= 70

    def test_case_3_same_device_diff_ip_drift_alert(self):
        """
        Case 3: Passkey fails, password succeeds on SAME device from DIFFERENT IP (e.g., VPN/proxy routing).
        Expected:
        - Classified as drift alert (drift_detected = True)
        - is_recovery_candidate = False
        - case_category = 'CASE_3_SAME_DEVICE_DIFF_IP'
        - Elevated risk score (>= 70)
        """
        vpn_ip = "198.51.100.77"
        raw_events = [
            {
                "time": "2026-11-12T10:00:00Z",
                "type": "LOGIN_ERROR",
                "realmId": "master",
                "userId": self.user_id,
                "ipAddress": self.primary_ip,
                "details": {
                    "auth_method": "passkey",
                    "device_id": self.primary_dev,
                    "location": self.primary_loc,
                    "error": "user_verification_failed"
                }
            },
            {
                "time": "2026-11-12T10:00:25Z",
                "type": "LOGIN",
                "realmId": "master",
                "userId": self.user_id,
                "ipAddress": vpn_ip,
                "details": {
                    "auth_method": "password",
                    "device_id": self.primary_dev,
                    "location": "Frankfurt, Germany"
                }
            }
        ]

        result = self.pipeline.process_raw_events(raw_events, provider="keycloak")
        assert len(result.alerts) == 1
        alert = result.alerts[0]

        assert alert.drift_detected is True
        assert alert.alert_type == "ASSURANCE_DRIFT"
        assert alert.is_recovery_candidate is False
        assert alert.context_evidence.is_primary_device_matched is True
        assert alert.context_evidence.is_primary_ip_matched is False
        assert alert.case_category == "CASE_3_SAME_DEVICE_DIFF_IP"
        assert alert.risk_assessment.score >= 70

    def test_case_4_diff_device_diff_ip_high_severity_drift(self):
        """
        Case 4: Passkey fails, password succeeds from DIFFERENT device AND DIFFERENT IP.
        Expected:
        - High severity drift alert (score >= 80, HIGH/CRITICAL severity)
        - is_recovery_candidate = False
        - case_category = 'CASE_4_DIFF_DEVICE_DIFF_IP'
        """
        attacker_dev = "rogue-kali-laptop"
        attacker_ip = "45.141.215.82"
        raw_events = [
            {
                "time": "2026-11-12T10:00:00Z",
                "type": "LOGIN_ERROR",
                "realmId": "master",
                "userId": self.user_id,
                "ipAddress": self.primary_ip,
                "details": {
                    "auth_method": "passkey",
                    "device_id": self.primary_dev,
                    "location": self.primary_loc,
                    "error": "fido2_timeout"
                }
            },
            {
                "time": "2026-11-12T10:00:40Z",
                "type": "LOGIN",
                "realmId": "master",
                "userId": self.user_id,
                "ipAddress": attacker_ip,
                "details": {
                    "auth_method": "password",
                    "device_id": attacker_dev,
                    "location": "Bucharest, Romania"
                }
            }
        ]

        result = self.pipeline.process_raw_events(raw_events, provider="keycloak")
        assert len(result.alerts) == 1
        alert = result.alerts[0]

        assert alert.drift_detected is True
        assert alert.alert_type == "ASSURANCE_DRIFT"
        assert alert.is_recovery_candidate is False
        assert alert.case_category == "CASE_4_DIFF_DEVICE_DIFF_IP"
        assert alert.risk_assessment.score >= 80
        assert alert.risk_assessment.severity in [RiskSeverity.HIGH, RiskSeverity.CRITICAL]

    def test_case_5_rogue_authenticator_registration_persistence(self):
        """
        Case 5: Passkey fails -> password login -> rogue WebAuthn authenticator registered.
        Expected:
        - CRITICAL severity alert (score >= 90)
        - authenticator_registered = True
        - case_category = 'CASE_5_ROGUE_AUTHENTICATOR_REGISTRATION'
        """
        attacker_dev = "rogue-surface-pro"
        attacker_ip = "185.220.101.5"
        raw_events = [
            {
                "time": "2026-11-12T10:00:00Z",
                "type": "LOGIN_ERROR",
                "realmId": "master",
                "userId": self.user_id,
                "ipAddress": self.primary_ip,
                "details": {
                    "auth_method": "passkey",
                    "device_id": self.primary_dev,
                    "location": self.primary_loc,
                    "error": "user_verification_failed"
                }
            },
            {
                "time": "2026-11-12T10:00:30Z",
                "type": "LOGIN",
                "realmId": "master",
                "userId": self.user_id,
                "ipAddress": attacker_ip,
                "details": {
                    "auth_method": "password",
                    "device_id": attacker_dev,
                    "location": "Amsterdam, Netherlands"
                }
            },
            {
                "time": "2026-11-12T10:01:00Z",
                "type": "REGISTER_AUTHENTICATOR",
                "realmId": "master",
                "userId": self.user_id,
                "ipAddress": attacker_ip,
                "details": {
                    "auth_method": "webauthn",
                    "device_id": attacker_dev,
                    "authenticator_id": "rogue-yubikey-sec99",
                    "location": "Amsterdam, Netherlands"
                }
            }
        ]

        result = self.pipeline.process_raw_events(raw_events, provider="keycloak")
        assert len(result.alerts) == 1
        alert = result.alerts[0]

        assert alert.drift_detected is True
        assert alert.context_evidence.authenticator_registered is True
        assert alert.context_evidence.authenticator_id == "rogue-yubikey-sec99"
        assert alert.case_category == "CASE_5_ROGUE_AUTHENTICATOR_REGISTRATION"
        assert alert.risk_assessment.score >= 90
        assert alert.risk_assessment.severity == RiskSeverity.CRITICAL

    def test_missing_context_fail_closed_invariant(self):
        """
        SECURITY INVARIANT: Missing context (device_id=None or ip_address=None)
        must NEVER be treated as a match. Must remain UNCERTAIN and never marked as genuine recovery.
        This test uses a separate user with NO registered baseline and NO device/IP on ANY event.
        """
        unknown_user = "api_client_no_context"
        raw_events = [
            {
                "time": "2026-11-12T10:00:00Z",
                "type": "LOGIN_ERROR",
                "realmId": "master",
                "userId": unknown_user,
                "ipAddress": None,
                "details": {
                    "auth_method": "passkey",
                    "device_id": None,
                    "location": None,
                    "error": "timeout"
                }
            },
            {
                "time": "2026-11-12T10:00:20Z",
                "type": "LOGIN",
                "realmId": "master",
                "userId": unknown_user,
                "ipAddress": None,
                "details": {
                    "auth_method": "password",
                    "device_id": None,
                    "location": None
                }
            }
        ]

        result = self.pipeline.process_raw_events(raw_events, provider="keycloak")
        assert len(result.alerts) == 1
        alert = result.alerts[0]

        # Must NOT be marked as genuine recovery
        assert alert.is_recovery_candidate is False
        assert alert.context_evidence.is_recovery_candidate is False
        # Device and IP context are absent — must remain None, never matched
        assert alert.context_evidence.is_primary_device_matched is None
        assert alert.context_evidence.is_primary_ip_matched is None
        # Drift alert must NOT be suppressed because context is unverified
        assert alert.drift_detected is True

