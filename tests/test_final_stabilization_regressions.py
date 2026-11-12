"""
AuthDrift: Comprehensive Regression Suite (25 Mandatory Stabilization Scenarios).
Verifies end-to-end deterministic behavior across detection, recovery suppression safety,
per-user baseline isolation, IPv4/IPv6 subnet continuity, invalid/missing telemetry handling,
LocationProfiler & velocity checks, threat intelligence resilience, API/dashboard compatibility,
and full Keycloak fixture integration.
"""

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

from backend.alerts.alert_generator import AlertGenerator
from backend.api import app
from backend.correlation.context_analyzer import ContextAnalyzer
from backend.correlation.location_profiler import LocationProfiler
from backend.detection.detection_rules import RULE_FAILED_STRONG_SUCCESS_WEAK
from backend.engine import AuthDriftEngine
from backend.models.assurance import AssuranceLevel
from backend.models.detection import ContextEvidence, DriftResult, RiskSeverity
from backend.models.event import AuthenticationEvent, EventCategory
from backend.pipeline.pipeline import AuthDriftPipeline
from backend.risk.risk_engine import RiskEngine
from backend.threat_intelligence.base import (
    IPReputationResult,
    STATUS_KNOWN_MALICIOUS,
    STATUS_UNKNOWN,
)
from backend.threat_intelligence.reputation_service import IPReputationService
from keycloak.generate_keycloak_fixtures import generate_keycloak_fixtures


def _make_kc_event(
    event_id: str,
    user_id: str,
    event_type: str,
    auth_method: str,
    device_id=None,
    ip_address=None,
    location=None,
    session_id="sess-1",
    authenticator_id=None,
    offset_sec: int = 0,
):
    base_ms = 1793400000000
    evt = {
        "id": event_id,
        "time": base_ms + (offset_sec * 1000),
        "type": event_type,
        "userId": f"usr-{user_id}",
        "sessionId": session_id,
        "ipAddress": ip_address,
        "details": {
            "username": user_id,
            "auth_method": auth_method,
            "device_id": device_id,
            "location": location,
        },
    }
    if authenticator_id:
        evt["details"]["authenticator_id"] = authenticator_id
    return evt


class TestMandatory25StabilizationRegressions:
    """Covers all 25 mandatory regression scenarios including final risk score and alert outcomes."""

    def _build_pipeline(self, rep_service=None):
        p = AuthDriftPipeline(reputation_service=rep_service)
        p.user_baselines = {
            "alice": {
                "primary_device": "macbook-alice",
                "known_devices": {"macbook-alice"},
                "primary_ip": "192.168.10.50",
                "known_ips": {"192.168.10.50"},
            },
            "bob_v6": {
                "primary_device": "pixel-bob",
                "known_devices": {"pixel-bob"},
                "primary_ip": "2001:db8:1234:5678::10",
                "known_ips": {"2001:db8:1234:5678::10"},
            },
        }
        return p

    # 1. Normal authentication
    def test_01_normal_authentication(self):
        p = self._build_pipeline()
        res = p.process_raw_events([
            _make_kc_event("n1", "alice", "LOGIN", "passkey", "macbook-alice", "192.168.10.50", "Bengaluru, India")
        ])
        alert = res.alerts[0]
        assert alert.drift_detected is False
        assert alert.alert_type == "INFORMATIONAL"
        assert alert.case_category == "ROUTINE"
        assert alert.risk_assessment.score == 0
        assert alert.risk_assessment.severity == RiskSeverity.LOW
        assert alert.is_actionable is False

    # 2. Same-device, same-IP fallback recovery
    def test_02_same_device_same_ip_recovery(self):
        p = self._build_pipeline()
        res = p.process_raw_events([
            _make_kc_event("r1", "alice", "LOGIN_ERROR", "passkey", "macbook-alice", "192.168.10.50", offset_sec=0),
            _make_kc_event("r2", "alice", "LOGIN", "password", "macbook-alice", "192.168.10.50", offset_sec=15),
        ])
        alert = res.alerts[0]
        assert alert.is_recovery_candidate is True
        assert alert.case_category == "CASE_1_SAME_DEVICE_SAME_IP"
        assert alert.recovery_classification == "GENUINE_RECOVERY"
        assert alert.drift_detected is False
        assert alert.alert_type == "INFORMATIONAL"
        assert alert.risk_assessment.score == 0
        assert alert.risk_assessment.severity == RiskSeverity.LOW

    # 3. Different device, same IP
    def test_03_different_device_same_ip(self):
        p = self._build_pipeline()
        res = p.process_raw_events([
            _make_kc_event("d1", "alice", "LOGIN_ERROR", "passkey", "macbook-alice", "192.168.10.50", offset_sec=0),
            _make_kc_event("d2", "alice", "LOGIN", "password", "rogue-device-99", "192.168.10.50", offset_sec=15),
        ])
        alert = res.alerts[0]
        assert alert.is_recovery_candidate is False
        assert alert.drift_detected is True
        assert alert.case_category == "CASE_2_DIFF_DEVICE_SAME_IP"
        assert alert.risk_assessment.score == 75
        assert alert.risk_assessment.severity == RiskSeverity.HIGH
        assert alert.is_actionable is True

    # 4. Same device, changed IP
    def test_04_same_device_changed_ip(self):
        p = self._build_pipeline()
        res = p.process_raw_events([
            _make_kc_event("i1", "alice", "LOGIN_ERROR", "passkey", "macbook-alice", "192.168.10.50", offset_sec=0),
            _make_kc_event("i2", "alice", "LOGIN", "password", "macbook-alice", "198.51.100.44", offset_sec=15),
        ])
        alert = res.alerts[0]
        assert alert.is_recovery_candidate is False
        assert alert.drift_detected is True
        assert alert.case_category == "CASE_3_SAME_DEVICE_DIFF_IP"
        assert alert.context_evidence.vpn_proxy_status == "NOT_VERIFIED"
        assert alert.risk_assessment.score == 55
        assert alert.risk_assessment.severity == RiskSeverity.MEDIUM

    # 5. Different device, changed IP
    def test_05_different_device_changed_ip(self):
        p = self._build_pipeline()
        res = p.process_raw_events([
            _make_kc_event("dd1", "alice", "LOGIN_ERROR", "passkey", "macbook-alice", "192.168.10.50", offset_sec=0),
            _make_kc_event("dd2", "alice", "LOGIN", "password", "rogue-box", "203.0.113.88", offset_sec=15),
        ])
        alert = res.alerts[0]
        assert alert.is_recovery_candidate is False
        assert alert.drift_detected is True
        assert alert.case_category == "CASE_4_DIFF_DEVICE_DIFF_IP"
        assert alert.risk_assessment.score == 75
        assert alert.risk_assessment.severity == RiskSeverity.HIGH

    # 6. Missing device and IP
    def test_06_missing_device_and_ip(self):
        p = self._build_pipeline()
        res = p.process_raw_events([
            _make_kc_event("m1", "alice", "LOGIN_ERROR", "passkey", None, None, offset_sec=0),
            _make_kc_event("m2", "alice", "LOGIN", "password", None, None, offset_sec=15),
        ])
        alert = res.alerts[0]
        assert alert.is_recovery_candidate is False
        assert alert.drift_detected is True
        assert alert.case_category == "UNCERTAIN_MISSING_CONTEXT"
        assert alert.context_evidence.is_primary_device_matched is None
        assert alert.context_evidence.is_primary_ip_matched is None
        assert alert.risk_assessment.score == 55

    # 7. Missing device only
    def test_07_missing_device_only(self):
        p = self._build_pipeline()
        res = p.process_raw_events([
            _make_kc_event("md1", "alice", "LOGIN_ERROR", "passkey", None, "192.168.10.50", offset_sec=0),
            _make_kc_event("md2", "alice", "LOGIN", "password", None, "192.168.10.50", offset_sec=15),
        ])
        alert = res.alerts[0]
        assert alert.is_recovery_candidate is False
        assert alert.drift_detected is True
        assert alert.context_evidence.device_id is None
        assert alert.context_evidence.is_primary_device_matched is None
        assert alert.case_category == "UNCERTAIN_MISSING_CONTEXT"
        assert alert.risk_assessment.score == 55

    # 8. Missing IP only
    def test_08_missing_ip_only(self):
        p = self._build_pipeline()
        res = p.process_raw_events([
            _make_kc_event("mi1", "alice", "LOGIN_ERROR", "passkey", "macbook-alice", None, offset_sec=0),
            _make_kc_event("mi2", "alice", "LOGIN", "password", "macbook-alice", None, offset_sec=15),
        ])
        alert = res.alerts[0]
        assert alert.is_recovery_candidate is False
        assert alert.drift_detected is True
        assert alert.context_evidence.ip_address is None
        assert alert.context_evidence.is_primary_ip_matched is None
        assert alert.case_category == "UNCERTAIN_MISSING_CONTEXT"
        assert alert.risk_assessment.score == 55

    # 9. Invalid IP address
    def test_09_invalid_ip_address_never_trusted(self):
        p = AuthDriftPipeline()
        p.user_baselines = {
            "badip_user": {
                "primary_device": "laptop-x",
                "known_devices": {"laptop-x"},
                "primary_ip": "not-an-ip",
                "known_ips": {"not-an-ip"},
            }
        }
        res = p.process_raw_events([
            _make_kc_event("iv1", "badip_user", "LOGIN_ERROR", "passkey", "laptop-x", "not-an-ip", offset_sec=0),
            _make_kc_event("iv2", "badip_user", "LOGIN", "password", "laptop-x", "not-an-ip", offset_sec=15),
        ])
        alert = res.alerts[0]
        assert alert.context_evidence.is_primary_ip_matched is None
        assert alert.is_recovery_candidate is False
        assert alert.drift_detected is True
        assert alert.risk_assessment.score >= 55

    # 10. IPv4 /24 subnet continuity
    def test_10_ipv4_24_subnet_continuity(self):
        p = self._build_pipeline()
        res = p.process_raw_events([
            _make_kc_event("v4_1", "alice", "LOGIN_ERROR", "passkey", "macbook-alice", "192.168.10.50", offset_sec=0),
            _make_kc_event("v4_2", "alice", "LOGIN", "password", "macbook-alice", "192.168.10.199", offset_sec=15),
        ])
        alert = res.alerts[0]
        assert alert.context_evidence.is_primary_ip_matched is True
        assert alert.is_recovery_candidate is True
        assert alert.drift_detected is False
        assert alert.risk_assessment.score == 0

    # 11. IPv6 /64 subnet continuity
    def test_11_ipv6_64_subnet_continuity(self):
        p = self._build_pipeline()
        res = p.process_raw_events([
            _make_kc_event("v6_1", "bob_v6", "LOGIN_ERROR", "passkey", "pixel-bob", "2001:db8:1234:5678::10", offset_sec=0),
            _make_kc_event("v6_2", "bob_v6", "LOGIN", "password", "pixel-bob", "2001:db8:1234:5678::abcd", offset_sec=15),
        ])
        alert = res.alerts[0]
        assert alert.context_evidence.is_primary_ip_matched is True
        assert alert.is_recovery_candidate is True
        assert alert.drift_detected is False
        assert alert.risk_assessment.score == 0

    # 12. New device baseline protection
    def test_12_new_device_never_automatically_trusted(self):
        p = self._build_pipeline()
        # First login uses an unfamiliar device; a subsequent login with that same device must still flag it as new
        res = p.process_raw_events([
            _make_kc_event("nd1", "alice", "LOGIN", "password", "unknown-tablet-99", "192.168.10.50", session_id="s1", offset_sec=0),
            _make_kc_event("nd2", "alice", "LOGIN", "password", "unknown-tablet-99", "192.168.10.50", session_id="s2", offset_sec=3600),
        ])
        assert len(res.alerts) == 2
        for alert in res.alerts:
            assert alert.context_evidence.is_new_device is True
            assert alert.risk_assessment.score >= 20
        assert "unknown-tablet-99" not in p.user_baselines["alice"]["known_devices"]

    # 13. Suspicious event baseline poisoning prevention
    def test_13_suspicious_failed_events_never_poison_baselines(self):
        p = self._build_pipeline()
        p.process_raw_events([
            _make_kc_event("sp1", "alice", "LOGIN_ERROR", "passkey", "attacker-dev", "203.0.113.5", "Pyongyang, KP", offset_sec=0),
            _make_kc_event("sp2", "alice", "LOGIN_ERROR", "password", "attacker-dev", "203.0.113.5", "Pyongyang, KP", offset_sec=10),
        ])
        # Verify alice baselines untouched and location profiler has no baseline from failed logins
        assert "attacker-dev" not in p.user_baselines["alice"]["known_devices"]
        assert "203.0.113.5" not in p.user_baselines["alice"]["known_ips"]
        prof = LocationProfiler(min_successful_observations=1)
        prof.build_profiles([
            AuthenticationEvent(
                event_id="f1", user_id="alice", timestamp=datetime.now(timezone.utc),
                event_type="LOGIN_ERROR", authentication_method="password", outcome="FAILURE",
                location="Pyongyang, KP",
            )
        ])
        assert prof.get_profile("alice") is None

    # 14. Known malicious IP
    def test_14_known_malicious_ip(self):
        mock_provider = MagicMock()
        mock_provider.provider_name = "AbuseIPDB"
        mock_provider.check_ip.return_value = IPReputationResult(
            ip_address="185.220.101.5",
            provider="AbuseIPDB",
            status=STATUS_KNOWN_MALICIOUS,
            abuse_confidence_score=95,
            total_reports=400,
        )
        p = self._build_pipeline(rep_service=IPReputationService(provider=mock_provider))
        res = p.process_raw_events([
            _make_kc_event("mal1", "alice", "LOGIN", "passkey", "macbook-alice", "185.220.101.5", "Bengaluru, India")
        ])
        alert = res.alerts[0]
        assert alert.ip_reputation.status == STATUS_KNOWN_MALICIOUS
        assert alert.priority == "HIGH_PRIORITY"
        assert alert.alert_type == "CONTEXTUAL_ANOMALY"
        assert alert.risk_assessment.score >= 23

    # 15. Threat intelligence provider unavailable
    def test_15_threat_intel_provider_unavailable_resilience(self):
        mock_provider = MagicMock()
        mock_provider.provider_name = "AbuseIPDB"
        mock_provider.check_ip.side_effect = RuntimeError("Upstream 503 unavailable")
        p = self._build_pipeline(rep_service=IPReputationService(provider=mock_provider))
        res = p.process_raw_events([
            _make_kc_event("tu1", "alice", "LOGIN", "passkey", "macbook-alice", "8.8.4.4", "Bengaluru, India")
        ])
        alert = res.alerts[0]
        assert alert.ip_reputation.status == STATUS_UNKNOWN
        assert alert.risk_assessment.score == 0
        assert alert.drift_detected is False

    # 16. Rogue authenticator registration
    def test_16_rogue_authenticator_registration(self):
        p = self._build_pipeline()
        res = p.process_raw_events([
            _make_kc_event("ra1", "alice", "LOGIN_ERROR", "passkey", "macbook-alice", "192.168.10.50", offset_sec=0),
            _make_kc_event("ra2", "alice", "LOGIN", "password", "rogue-box", "203.0.113.10", offset_sec=10),
            _make_kc_event("ra3", "alice", "REGISTER_AUTHENTICATOR", "webauthn", "rogue-box", "203.0.113.10", authenticator_id="rogue-key-99", offset_sec=20),
        ])
        alert = res.alerts[0]
        assert alert.drift_detected is True
        assert alert.case_category == "CASE_5_ROGUE_AUTHENTICATOR_REGISTRATION"
        assert alert.context_evidence.authenticator_registered is True
        assert alert.risk_assessment.score == 100
        assert alert.risk_assessment.severity == RiskSeverity.CRITICAL
        assert alert.priority == "HIGH_PRIORITY"

    # 17. Location baseline below observation threshold
    def test_17_location_baseline_below_threshold(self):
        p = self._build_pipeline()
        res = p.process_raw_events([
            _make_kc_event("lb1", "alice", "LOGIN", "passkey", "macbook-alice", "192.168.10.50", "Bengaluru, India", session_id="s1", offset_sec=0),
            _make_kc_event("lb2", "alice", "LOGIN", "passkey", "macbook-alice", "192.168.10.50", "Frankfurt, Germany", session_id="s2", offset_sec=7200),
        ])
        # Second session only has 1 prior observation (< min_successful_observations=2), so status stays UNKNOWN
        second_alert = res.alerts[1]
        assert second_alert.context_evidence.primary_location is None
        assert second_alert.context_evidence.location_status == "UNKNOWN"
        assert second_alert.context_evidence.is_location_changed is None
        assert second_alert.risk_assessment.score == 0

    # 18. Impossible travel with sufficient evidence
    def test_18_impossible_travel_with_sufficient_evidence(self):
        p = self._build_pipeline()
        res = p.process_raw_events([
            _make_kc_event("it1", "alice", "LOGIN", "passkey", "macbook-alice", "192.168.10.50", "Bengaluru, India", offset_sec=0),
            _make_kc_event("it2", "alice", "REFRESH_TOKEN", "refresh_token", "macbook-alice", "198.51.100.10", "Frankfurt, Germany", offset_sec=60),
        ])
        alert = res.alerts[0]
        imp = [a for a in alert.context_anomalies if a.is_impossible_travel]
        assert len(imp) == 1
        assert imp[0].velocity_kmh > 900
        assert alert.risk_assessment.score == 15
        assert alert.alert_type == "CONTEXTUAL_ANOMALY"

    # 19. Multiple sessions for same user (session isolation)
    def test_19_multiple_sessions_same_user_isolated(self):
        p = self._build_pipeline()
        res = p.process_raw_events([
            _make_kc_event("ms1", "alice", "LOGIN", "passkey", "macbook-alice", "192.168.10.50", "Bengaluru, India", session_id="sess-ok", offset_sec=0),
            _make_kc_event("ms2", "alice", "LOGIN_ERROR", "passkey", "macbook-alice", "192.168.10.50", "Bengaluru, India", session_id="sess-bad", offset_sec=3600),
            _make_kc_event("ms3", "alice", "LOGIN", "password", "evil-laptop", "203.0.113.77", "Berlin, Germany", session_id="sess-bad", offset_sec=3615),
        ])
        by_sess = {a.session_id: a for a in res.alerts}
        assert by_sess["sess-ok"].drift_detected is False
        assert by_sess["sess-ok"].risk_assessment.score == 0
        assert by_sess["sess-bad"].drift_detected is True
        assert by_sess["sess-bad"].risk_assessment.score >= 75

    # 20. Multiple users with separate baselines (no leakage)
    def test_20_multiple_users_separate_baselines(self):
        p = AuthDriftPipeline()
        p.user_baselines = {
            "user_a": {
                "primary_device": "dev-a-only",
                "known_devices": {"dev-a-only"},
                "primary_ip": "10.0.1.5",
                "known_ips": {"10.0.1.5"},
            },
            "user_b": {
                "primary_device": "dev-b-only",
                "known_devices": {"dev-b-only"},
                "primary_ip": "10.0.2.5",
                "known_ips": {"10.0.2.5"},
            },
        }
        res = p.process_raw_events([
            _make_kc_event("ua1", "user_a", "LOGIN", "passkey", "dev-b-only", "10.0.2.5", session_id="sa", offset_sec=0),
            _make_kc_event("ub1", "user_b", "LOGIN", "passkey", "dev-b-only", "10.0.2.5", session_id="sb", offset_sec=10),
        ])
        alerts = {a.user_id: a for a in res.alerts}
        assert alerts["user_a"].context_evidence.is_new_device is True
        assert alerts["user_a"].context_evidence.is_primary_ip_matched is False
        assert alerts["user_a"].risk_assessment.score == 20
        assert alerts["user_b"].context_evidence.is_new_device is False
        assert alerts["user_b"].context_evidence.is_primary_ip_matched is True
        assert alerts["user_b"].risk_assessment.score == 0

    # 21. Session lifecycle and token refresh handling + mixed naive/aware timestamps
    def test_21_session_lifecycle_refresh_and_mixed_timestamps(self):
        detector = AuthDriftEngine().drift_detector
        events = [
            AuthenticationEvent(
                event_id="e1", user_id="alice", timestamp=datetime(2026, 11, 12, 10, 0, 0),
                event_type="LOGIN", authentication_method="passkey", outcome="SUCCESS",
                event_category=EventCategory.AUTHENTICATION.value,
            ),
            AuthenticationEvent(
                event_id="e2", user_id="alice", timestamp=datetime(2026, 11, 12, 10, 5, 0, tzinfo=timezone.utc),
                event_type="REFRESH_TOKEN", authentication_method="refresh_token", outcome="SUCCESS",
                event_category=EventCategory.SESSION_LIFECYCLE.value,
            ),
        ]
        drift = detector.detect_drift(events)
        assert drift.drift_detected is False

    # 22. API alert filtering
    def test_22_api_alert_filtering(self):
        client = TestClient(app)
        client.post("/api/scenarios/all/load")
        drift_resp = client.get("/api/alerts?drift_only=true")
        assert drift_resp.status_code == 200
        assert all(a["drift_detected"] is True for a in drift_resp.json()["alerts"])

        crit_resp = client.get("/api/alerts?severity=CRITICAL")
        assert crit_resp.status_code == 200
        assert all(a["risk_assessment"]["severity"] == "CRITICAL" for a in crit_resp.json()["alerts"])

        empty_run = client.post("/api/pipeline/run", json={"provider": "keycloak", "events": []})
        assert empty_run.status_code == 200
        assert empty_run.json()["metrics"]["reconstructed_journeys"] == 0
        client.post("/api/scenarios/all/load")

    # 23. Dashboard/API response compatibility & removed LLM endpoints
    def test_23_dashboard_and_api_compatibility_no_llm_routes(self):
        client = TestClient(app)
        assert client.get("/api/llm/fallback-memory").status_code == 404
        assert client.post("/api/llm/calibrate-journey", json={}).status_code == 404
        alerts = client.get("/api/alerts").json()["alerts"]
        assert len(alerts) > 0
        sample = alerts[0]
        assert "vpn_proxy_status" in sample["context_evidence"]
        assert sample["context_evidence"]["vpn_proxy_status"] == "NOT_VERIFIED"

    # 24. Genuine recovery with independent malicious signal NEVER suppressed
    def test_24_recovery_never_suppresses_independent_malicious_signal(self):
        # Test 24a: End-to-end with known malicious IP on matching primary device & IP
        mock_provider = MagicMock()
        mock_provider.provider_name = "AbuseIPDB"
        mock_provider.check_ip.return_value = IPReputationResult(
            ip_address="45.141.215.82",
            provider="AbuseIPDB",
            status=STATUS_KNOWN_MALICIOUS,
            abuse_confidence_score=90,
            total_reports=150,
        )
        p = AuthDriftPipeline(reputation_service=IPReputationService(provider=mock_provider))
        p.user_baselines = {
            "target_user": {
                "primary_device": "macbook-pro",
                "known_devices": {"macbook-pro"},
                "primary_ip": "45.141.215.82",
                "known_ips": {"45.141.215.82"},
            }
        }
        res = p.process_raw_events([
            _make_kc_event("mr1", "target_user", "LOGIN_ERROR", "passkey", "macbook-pro", "45.141.215.82", offset_sec=0),
            _make_kc_event("mr2", "target_user", "LOGIN", "password", "macbook-pro", "45.141.215.82", offset_sec=15),
        ])
        alert = res.alerts[0]
        assert alert.is_recovery_candidate is False
        assert alert.drift_detected is True
        assert alert.risk_assessment.score >= 70
        assert alert.priority == "HIGH_PRIORITY"

        # Test 24b: Direct RiskEngine + AlertGenerator guard even if is_recovery_candidate=True is forced alongside rogue authenticator
        drift = DriftResult(
            drift_detected=True,
            reason="Failed passkey followed by password",
            previous_method="passkey",
            previous_assurance=AssuranceLevel.HIGH,
            current_method="password",
            current_assurance=AssuranceLevel.LOW,
            transition_type=RULE_FAILED_STRONG_SUCCESS_WEAK,
        )
        ev = ContextEvidence(
            is_new_device=False,
            device_id="macbook-pro",
            ip_address="192.168.1.10",
            authenticator_registered=True,
            authenticator_id="rogue-01",
            is_recovery_candidate=True,
        )
        risk = RiskEngine().evaluate_risk(drift, ev)
        alert_direct = AlertGenerator().generate_alert([], drift, ev, risk)
        assert risk.score >= 80
        assert alert_direct.is_recovery_candidate is False
        assert alert_direct.drift_detected is True
        assert alert_direct.is_actionable is True

    # 25. Full Keycloak fixture integration
    def test_25_full_keycloak_fixture_integration(self):
        raw_events = generate_keycloak_fixtures()
        p = AuthDriftPipeline()
        res = p.process_raw_events(raw_events, provider="keycloak")
        by_user = {a.user_id: a for a in res.alerts}
        assert len(by_user) == 11

        # Frank (192.168.1.40) contextual fields populated cleanly; single-session primary_location stays None
        frank = by_user["frank"]
        assert frank.context_evidence.device_id == "frank-new-laptop-02"
        assert frank.context_evidence.is_new_device is True
        assert frank.context_evidence.location == "Bangalore, IN"
        assert frank.context_evidence.primary_location is None
        assert frank.context_evidence.location_status == "UNKNOWN"
        assert frank.context_evidence.is_primary_ip_matched is None  # No global IP baseline configured
        assert frank.risk_assessment.score >= 75

        # Heidi (TC08) stays strictly null-context
        heidi = by_user["heidi"]
        assert heidi.context_evidence.device_id is None
        assert heidi.context_evidence.ip_address is None
        assert heidi.context_evidence.location is None
        assert heidi.is_recovery_candidate is False
        assert heidi.drift_detected is True
