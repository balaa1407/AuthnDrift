"""
AuthDrift: Comprehensive Simulation Test Suite (Categories A through E).
Validates end-to-end detection, contextual anomalies, assurance drift, recovery journeys,
and IP threat intelligence with deterministic evaluation metrics.

Simulation Categories:
- Category A: Informational Scenarios (known device/IP, normal passkey/password)
- Category B: Contextual Anomaly Scenarios (new device, changed IP, combined, unknown)
- Category C: Assurance Drift Scenarios (Rule A fallback, Rule B step-down, persistence registration)
- Category D: Recovery Scenarios (device migration, incomplete context, legitimate recovery)
- Category E: Threat Intelligence Scenarios (high-risk public IP, clean IP, private IP, rate limits, timeouts)
"""

from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock
import pytest

from backend.models.event import AuthenticationEvent, EventCategory
from backend.models.detection import RiskSeverity, AlertPriority, DriftResult, ContextEvidence
from backend.models.assurance import AssuranceLevel
from backend.engine import AuthDriftEngine
from backend.detection.detection_rules import (
    DriftDetectionConfig,
    RULE_FAILED_STRONG_SUCCESS_WEAK,
    RULE_CROSS_CEREMONY_DOWNGRADE,
    RULE_STEP_UP_AUTHENTICATION
)
from backend.threat_intelligence.base import (
    IPReputationResult,
    STATUS_KNOWN_MALICIOUS,
    STATUS_SUSPICIOUS,
    STATUS_CLEAN,
    STATUS_PRIVATE,
    STATUS_UNKNOWN,
)
from backend.threat_intelligence.reputation_service import IPReputationService
from backend.pipeline.pipeline import AuthDriftPipeline


def make_sim_event(
    user_id: str,
    method: str,
    outcome: str = "SUCCESS",
    device_id: Optional[str] = "laptop-corp-01",
    location: Optional[str] = "Bangalore, IN",
    ip_address: Optional[str] = "192.168.1.10",
    authenticator_id: Optional[str] = None,
    event_type: str = "LOGIN",
    event_category: EventCategory = EventCategory.AUTHENTICATION,
    delta_seconds: int = 0
) -> AuthenticationEvent:
    base = datetime(2026, 10, 30, 14, 0, 0, tzinfo=timezone.utc)
    return AuthenticationEvent(
        event_id=f"sim-{user_id}-{delta_seconds}",
        user_id=user_id,
        timestamp=base + timedelta(seconds=delta_seconds),
        event_type=event_type,
        event_category=event_category.value,
        authentication_method=method,
        outcome=outcome,
        device_id=device_id,
        location=location,
        ip_address=ip_address,
        authenticator_id=authenticator_id
    )


class TestSimulationSuite:
    """Execution of simulation categories A through E."""

    @classmethod
    def setup_class(cls):
        cls.known_devices = {"laptop-corp-01", "pixel-9-corp"}
        cls.known_locations = {"Bangalore, IN"}
        cls.engine = AuthDriftEngine()

    # =========================================================================
    # CATEGORY A: INFORMATIONAL SCENARIOS
    # =========================================================================

    def test_sim_a01_normal_passkey_known_context(self):
        """
        Category A01: Normal passkey authentication on known device and known IP.
        Expected: High assurance, no drift, low risk (score=0), alert_type=INFORMATIONAL.
        """
        journey = [
            make_sim_event("alice", "passkey", "SUCCESS", device_id="laptop-corp-01", ip_address="192.168.1.10")
        ]
        alert = self.engine.evaluate_journey(
            journey,
            known_devices=self.known_devices,
            known_locations=self.known_locations
        )

        assert alert.alert_type == "INFORMATIONAL"
        assert alert.drift_detected is False
        assert alert.risk_assessment.score == 0
        assert alert.risk_assessment.severity == RiskSeverity.LOW
        assert alert.is_actionable is False
        assert "No assurance degradation detected" in alert.explanation

    def test_sim_a02_normal_password_known_context(self):
        """
        Category A02: Normal password authentication on known device and known IP.
        Expected: Low assurance assigned without degradation, no drift, alert_type=INFORMATIONAL.
        """
        journey = [
            make_sim_event("alice_pwd", "password", "SUCCESS", device_id="laptop-corp-01", ip_address="192.168.1.10")
        ]
        alert = self.engine.evaluate_journey(
            journey,
            known_devices=self.known_devices,
            known_locations=self.known_locations
        )

        assert alert.alert_type == "INFORMATIONAL"
        assert alert.drift_detected is False
        assert alert.risk_assessment.score == 0
        assert alert.is_actionable is False

    # =========================================================================
    # CATEGORY B: CONTEXTUAL ANOMALY SCENARIOS
    # =========================================================================

    def test_sim_b01_new_device_only(self):
        """
        Category B01: Successful authentication from a new unfamiliar device, known IP.
        Expected: Contextual anomaly alert, no assurance drift, elevated context score.
        """
        journey = [
            make_sim_event("bob", "password", "SUCCESS", device_id="unfamiliar-tablet-99", ip_address="192.168.1.10")
        ]
        alert = self.engine.evaluate_journey(
            journey,
            known_devices=self.known_devices,
            known_locations=self.known_locations
        )

        assert alert.alert_type == "CONTEXTUAL_ANOMALY"
        assert alert.drift_detected is False
        assert alert.context_evidence.is_new_device is True
        assert alert.risk_assessment.score == 20  # weight_new_device = 20
        assert "new device" in alert.explanation.lower()

    def test_sim_b02_changed_ip_only(self):
        """
        Category B02: Successful authentication from a changed IP across events on known device.
        Expected: IP change detected in context anomalies, alert_type=CONTEXTUAL_ANOMALY.
        """
        journey = [
            make_sim_event("carol", "password", "SUCCESS", device_id="laptop-corp-01", ip_address="192.168.1.10", delta_seconds=0),
            make_sim_event("carol", "password", "SUCCESS", device_id="laptop-corp-01", ip_address="192.168.1.55", delta_seconds=60)
        ]
        alert = self.engine.evaluate_journey(
            journey,
            known_devices=self.known_devices,
            known_locations=self.known_locations
        )

        assert alert.alert_type == "CONTEXTUAL_ANOMALY"
        assert alert.drift_detected is False
        assert any(a.anomaly_type == "IP_CHANGE" for a in alert.context_evidence.context_anomalies)

    def test_sim_b03_new_device_combined_with_changed_location(self):
        """
        Category B03: New device combined with location change (Berlin, Germany).
        Expected: Multiple contextual signals correlated, elevated risk score (35).
        """
        journey = [
            make_sim_event("dave", "password", "SUCCESS", device_id="foreign-phone-01", location="Berlin, Germany", delta_seconds=0)
        ]
        alert = self.engine.evaluate_journey(
            journey,
            known_devices=self.known_devices,
            known_locations=self.known_locations
        )

        assert alert.alert_type == "CONTEXTUAL_ANOMALY"
        assert alert.drift_detected is False
        assert alert.context_evidence.is_new_device is True
        assert alert.context_evidence.is_location_changed is True
        assert alert.risk_assessment.score == 35  # 20 (device) + 15 (location)
        assert alert.risk_assessment.severity == RiskSeverity.MEDIUM

    def test_sim_b04_missing_device_and_location_context(self):
        """
        Category B04: Authentication with missing/unknown device and IP metadata.
        Expected: Safe null handling, does not invent anomalies or crash.
        """
        journey = [
            make_sim_event("eve_missing", "passkey", "SUCCESS", device_id=None, location=None, ip_address=None)
        ]
        alert = self.engine.evaluate_journey(
            journey,
            known_devices=self.known_devices,
            known_locations=self.known_locations
        )

        assert alert.alert_type == "INFORMATIONAL"
        assert alert.drift_detected is False
        assert alert.context_evidence.device_id is None
        assert alert.context_evidence.is_new_device is None
        assert alert.risk_assessment.score == 0

    # =========================================================================
    # CATEGORY C: ASSURANCE DRIFT SCENARIOS
    # =========================================================================

    def test_sim_c01_active_fallback_downgrade_rule_a(self):
        """
        Category C01: Failed strong authentication (passkey) followed by password success (Rule A).
        Expected: ASSURANCE_DRIFT alert, transition_type=FAILED_STRONG_SUCCESS_WEAK, HIGH -> LOW.
        """
        journey = [
            make_sim_event("frank", "passkey", "FAILURE", delta_seconds=0),
            make_sim_event("frank", "password", "SUCCESS", delta_seconds=15)
        ]
        alert = self.engine.evaluate_journey(journey)

        assert alert.alert_type == "ASSURANCE_DRIFT"
        assert alert.drift_detected is True
        assert alert.drift_result.transition_type == RULE_FAILED_STRONG_SUCCESS_WEAK
        assert alert.drift_result.previous_assurance == AssuranceLevel.HIGH
        assert alert.drift_result.current_assurance == AssuranceLevel.LOW
        assert alert.risk_assessment.score >= 40

    def test_sim_c02_cross_ceremony_step_down_rule_b(self):
        """
        Category C02: Consecutive successful authentications with step-down assurance (Rule B).
        Expected: ASSURANCE_DRIFT alert under configured Rule B.
        """
        from backend.detection.drift_detector import DriftDetector
        drift_detector_rule_b = DriftDetector(
            config=DriftDetectionConfig(
                detect_any_downgrade=True,
                require_prior_failure=False
            )
        )
        engine_rule_b = AuthDriftEngine(drift_detector=drift_detector_rule_b)
        journey = [
            make_sim_event("grace", "passkey", "SUCCESS", delta_seconds=0),
            make_sim_event("grace", "password", "SUCCESS", delta_seconds=60)
        ]
        alert = engine_rule_b.evaluate_journey(journey)

        assert alert.alert_type == "ASSURANCE_DRIFT"
        assert alert.drift_detected is True
        assert alert.drift_result.transition_type == RULE_CROSS_CEREMONY_DOWNGRADE
        assert alert.drift_result.previous_assurance == AssuranceLevel.HIGH
        assert alert.drift_result.current_assurance == AssuranceLevel.LOW

    def test_sim_c03_downgrade_followed_by_rogue_authenticator_registration(self):
        """
        Category C03: Downgrade fallback followed by rogue authenticator registration.
        Expected: CRITICAL severity, score >= 80, persistence flag active.
        """
        journey = [
            make_sim_event("heidi", "passkey", "FAILURE", delta_seconds=0),
            make_sim_event("heidi", "password", "SUCCESS", delta_seconds=15),
            make_sim_event(
                "heidi",
                "webauthn",
                "SUCCESS",
                event_type="REGISTER_AUTHENTICATOR",
                event_category=EventCategory.ACCOUNT_LIFECYCLE,
                authenticator_id="rogue-hardware-token",
                delta_seconds=30
            )
        ]
        alert = self.engine.evaluate_journey(journey)

        assert alert.alert_type == "ASSURANCE_DRIFT"
        assert alert.drift_detected is True
        assert alert.context_evidence.authenticator_registered is True
        assert alert.risk_assessment.score >= 80
        assert alert.risk_assessment.severity == RiskSeverity.CRITICAL

    # =========================================================================
    # CATEGORY D: RECOVERY SCENARIOS
    # =========================================================================

    def test_sim_d01_legitimate_device_migration_with_caveat(self):
        """
        Category D01: Passkey failure -> password success on same known device & same IP.
        Expected:
        - Classify this as a legitimate recovery candidate.
        - Do not automatically generate an assurance-drift alert (alert_type=INFORMATIONAL, drift_detected=False).
        - Do not assign an artificial risk penalty (score=0, LOW severity).
        - Preserve the authentication journey and its contextual evidence.
        """
        journey = [
            make_sim_event("ivan", "passkey", "FAILURE", device_id="laptop-corp-01", ip_address="192.168.1.10", delta_seconds=0),
            make_sim_event("ivan", "password", "SUCCESS", device_id="laptop-corp-01", ip_address="192.168.1.10", delta_seconds=20)
        ]
        alert = self.engine.evaluate_journey(journey, known_devices=self.known_devices)

        # 1. Recovery candidate classification
        assert alert.is_recovery_candidate is True
        assert alert.context_evidence.is_recovery_candidate is True

        # 2. No automatic assurance-drift alert
        assert alert.alert_type == "INFORMATIONAL"
        assert alert.drift_detected is False
        assert alert.is_actionable is False
        assert alert.priority == "INFORMATIONAL"

        # 3. No artificial risk penalty
        assert alert.risk_assessment.score == 0
        assert alert.risk_assessment.severity == RiskSeverity.LOW

        # 4. Preserved journey & contextual evidence
        assert len(alert.failed_authentications) == 1
        assert alert.failed_authentications[0]["authentication_method"] == "passkey"
        assert alert.context_evidence.device_id == "laptop-corp-01"
        assert alert.context_evidence.is_new_device is False
        assert alert.drift_result.transition_type == RULE_FAILED_STRONG_SUCCESS_WEAK
        assert "recovery candidate identified" in alert.explanation.lower()

    def test_sim_d03_fallback_without_known_device_retains_drift(self):
        """
        Category D03: Fallback without verified known device context retains drift alert.
        """
        journey = [
            make_sim_event("frank_mig", "passkey", "FAILURE", device_id=None, delta_seconds=0),
            make_sim_event("frank_mig", "password", "SUCCESS", device_id=None, delta_seconds=15)
        ]
        alert = self.engine.evaluate_journey(journey)
        assert alert.drift_detected is True
        assert alert.alert_type == "ASSURANCE_DRIFT"
        assert alert.is_recovery_candidate is False
        assert "not definitive proof of an active compromise" in alert.explanation

    def test_sim_d02_legitimate_step_up_authentication(self):
        """
        Category D02: Password authentication followed by passkey step-up.
        Expected: Step-up recognized as security enhancement; no drift.
        """
        journey = [
            make_sim_event("judy", "password", "SUCCESS", delta_seconds=0),
            make_sim_event("judy", "passkey", "SUCCESS", delta_seconds=30)
        ]
        alert = self.engine.evaluate_journey(journey)

        assert alert.drift_detected is False
        assert alert.drift_result.transition_type == RULE_STEP_UP_AUTHENTICATION
        assert alert.risk_assessment.score == 0

    # =========================================================================
    # CATEGORY E: THREAT INTELLIGENCE SCENARIOS
    # =========================================================================

    def test_sim_e01_public_ip_high_reputation_risk(self):
        """
        Category E01: Public IP with 85% abuse confidence score from AbuseIPDB.
        Expected: Flagged as KNOWN_MALICIOUS, Factor 7 triggered, priority escalated to HIGH_PRIORITY.
        """
        mock_provider = MagicMock()
        mock_provider.provider_name = "AbuseIPDB"
        mock_provider.check_ip.return_value = IPReputationResult(
            ip_address="118.25.6.39",
            status=STATUS_KNOWN_MALICIOUS,
            abuse_confidence_score=85,
            total_reports=34,
            provider="AbuseIPDB"
        )
        service = IPReputationService(provider=mock_provider)
        engine = AuthDriftEngine(reputation_service=service)

        journey = [
            make_sim_event("mallory", "password", "SUCCESS", ip_address="118.25.6.39")
        ]
        alert = engine.evaluate_journey(journey)

        assert alert.ip_reputation is not None
        assert alert.ip_reputation.status == STATUS_KNOWN_MALICIOUS
        assert alert.priority == AlertPriority.HIGH_PRIORITY
        assert alert.risk_assessment.score >= 20
        assert "threat intelligence from AbuseIPDB flagged IP as KNOWN_MALICIOUS" in alert.explanation

    def test_sim_e02_public_ip_clean_reputation(self):
        """
        Category E02: Public IP with 0% abuse score.
        Expected: Flagged as CLEAN, zero risk score contribution.
        """
        mock_provider = MagicMock()
        mock_provider.provider_name = "AbuseIPDB"
        mock_provider.check_ip.return_value = IPReputationResult(
            ip_address="8.8.8.8",
            status=STATUS_CLEAN,
            abuse_confidence_score=0,
            provider="AbuseIPDB"
        )
        service = IPReputationService(provider=mock_provider)
        engine = AuthDriftEngine(reputation_service=service)

        journey = [
            make_sim_event("oscar", "password", "SUCCESS", ip_address="8.8.8.8")
        ]
        alert = engine.evaluate_journey(journey)

        assert alert.ip_reputation is not None
        assert alert.ip_reputation.status == STATUS_CLEAN
        assert alert.risk_assessment.score == 0

    def test_sim_e03_private_ip_safe_handling(self):
        """
        Category E03: Private IP (192.168.1.10).
        Expected: Status PRIVATE, external provider skipped, no risk score impact.
        """
        mock_provider = MagicMock()
        service = IPReputationService(provider=mock_provider)
        engine = AuthDriftEngine(reputation_service=service)

        journey = [
            make_sim_event("peggy", "password", "SUCCESS", ip_address="192.168.1.10")
        ]
        alert = engine.evaluate_journey(journey)

        assert alert.ip_reputation.status == STATUS_PRIVATE
        mock_provider.check_ip.assert_not_called()
        assert alert.risk_assessment.score == 0

    def test_sim_e04_invalid_and_missing_ip(self):
        """
        Category E04: Invalid and missing IP address strings.
        Expected: Status UNKNOWN, external provider skipped, no crash.
        """
        mock_provider = MagicMock()
        service = IPReputationService(provider=mock_provider)
        engine = AuthDriftEngine(reputation_service=service)

        for bad_ip in ["999.999.999.999", "invalid-ip-string"]:
            journey = [
                make_sim_event("rupert", "password", "SUCCESS", ip_address=bad_ip)
            ]
            alert = engine.evaluate_journey(journey)
            assert alert.ip_reputation is not None
            assert alert.ip_reputation.status == STATUS_UNKNOWN
            mock_provider.check_ip.assert_not_called()

        # Missing IP case
        journey_none = [
            make_sim_event("rupert_none", "password", "SUCCESS", ip_address=None)
        ]
        alert_none = engine.evaluate_journey(journey_none)
        assert alert_none.ip_reputation is None
        # Direct service query with None returns UNKNOWN
        assert service.get_ip_reputation(None).status == STATUS_UNKNOWN
        mock_provider.check_ip.assert_not_called()

    def test_sim_e05_provider_timeout_resilience(self):
        """
        Category E05: AbuseIPDB provider times out.
        Expected: Fails safely to UNKNOWN; authentication analysis completes normally.
        """
        mock_provider = MagicMock()
        mock_provider.provider_name = "AbuseIPDB"
        mock_provider.check_ip.return_value = IPReputationResult(
            ip_address="118.25.6.39",
            status=STATUS_UNKNOWN,
            provider="AbuseIPDB"
        )
        service = IPReputationService(provider=mock_provider)
        engine = AuthDriftEngine(reputation_service=service)

        journey = [
            make_sim_event("sybil", "passkey", "FAILURE", ip_address="118.25.6.39", delta_seconds=0),
            make_sim_event("sybil", "password", "SUCCESS", ip_address="118.25.6.39", delta_seconds=15)
        ]
        alert = engine.evaluate_journey(journey)

        # Drift detection works even when threat intel returns UNKNOWN
        assert alert.drift_detected is True
        assert alert.ip_reputation.status == STATUS_UNKNOWN
        assert alert.risk_assessment.score >= 40

    def test_sim_e06_provider_rate_limit_resilience(self):
        """
        Category E06: AbuseIPDB returns HTTP 429 rate limit.
        Expected: Fails safely to UNKNOWN; core analysis unaffected.
        """
        mock_provider = MagicMock()
        mock_provider.provider_name = "AbuseIPDB"
        mock_provider.check_ip.return_value = IPReputationResult(
            ip_address="118.25.6.39",
            status=STATUS_UNKNOWN,
            provider="AbuseIPDB"
        )
        service = IPReputationService(provider=mock_provider)
        engine = AuthDriftEngine(reputation_service=service)

        journey = [
            make_sim_event("trent", "password", "SUCCESS", ip_address="118.25.6.39")
        ]
        alert = engine.evaluate_journey(journey)

        assert alert.ip_reputation.status == STATUS_UNKNOWN
        assert alert.risk_assessment.score == 0

    # =========================================================================
    # FILTERING & ALERT DISCRIMINATION
    # =========================================================================

    def test_sim_filtering_and_classification(self):
        """
        Verifies discrete alert classification: INFORMATIONAL vs CONTEXTUAL_ANOMALY vs ASSURANCE_DRIFT.
        """
        # 1. Informational
        j_info = [make_sim_event("u1", "passkey", "SUCCESS", device_id="laptop-corp-01")]
        a_info = self.engine.evaluate_journey(j_info, known_devices=self.known_devices)
        assert a_info.alert_type == "INFORMATIONAL"

        # 2. Contextual anomaly
        j_ctx = [make_sim_event("u2", "passkey", "SUCCESS", device_id="brand-new-phone-99")]
        a_ctx = self.engine.evaluate_journey(j_ctx, known_devices=self.known_devices)
        assert a_ctx.alert_type == "CONTEXTUAL_ANOMALY"

        # 3. Assurance drift
        j_drift = [
            make_sim_event("u3", "passkey", "FAILURE", delta_seconds=0),
            make_sim_event("u3", "password", "SUCCESS", delta_seconds=10)
        ]
        a_drift = self.engine.evaluate_journey(j_drift)
        assert a_drift.alert_type == "ASSURANCE_DRIFT"


class TestResearchPaperSyntheticBenchmark:
    """
    Validates AuthDrift against the 100-journey synthetic dataset directly grounded in
    academic research literature (Lyastani et al. S&P 2020, Wiefling et al. ASIACCS 2020,
    Kent LANL 2016, Bonneau et al. S&P 2012).
    """

    def setup_method(self):
        from backend.synthetic_data.research_dataset_generator import (
            generate_research_synthetic_dataset,
            KNOWN_BENCHMARK_DEVICES
        )
        self.dataset = generate_research_synthetic_dataset()
        self.known_devices = KNOWN_BENCHMARK_DEVICES

        # Create mock reputation service so no external network requests are made
        mock_provider = MagicMock()
        mock_provider.provider_name = "AbuseIPDB"

        malicious_ips = {
            "118.25.6.39", "185.220.101.5", "194.26.29.42", "45.141.215.82",
            "185.196.8.11", "91.240.118.15", "193.142.146.10", "45.154.255.88",
            "194.26.29.99", "185.220.101.77"
        }

        def mock_check(ip: str):
            if ip in malicious_ips:
                return IPReputationResult(
                    ip_address=ip,
                    status=STATUS_KNOWN_MALICIOUS,
                    abuse_confidence_score=85,
                    total_reports=142,
                    is_whitelisted=False,
                    country_code="RU",
                    usage_type="Data Center / Tor",
                    isp="Bulletproof Hosting",
                    provider="AbuseIPDB"
                )
            return IPReputationResult(
                ip_address=ip,
                status=STATUS_CLEAN,
                abuse_confidence_score=0,
                total_reports=0,
                provider="AbuseIPDB"
            )

        mock_provider.check_ip.side_effect = mock_check
        self.reputation_service = IPReputationService(provider=mock_provider)
        self.pipeline = AuthDriftPipeline(reputation_service=self.reputation_service)
        self.pipeline.known_devices.update(self.known_devices)

    def test_research_dataset_structure_and_citations(self):
        """Verifies metadata and academic citations in synthetic benchmark dataset."""
        meta = self.dataset["metadata"]
        assert meta["total_journeys"] == 100
        assert meta["total_raw_events"] > 150
        assert meta["distribution"]["ROUTINE_NORMAL"] == 60
        assert meta["distribution"]["BENIGN_RECOVERY"] == 15
        assert meta["distribution"]["ADVERSARIAL_DRIFT"] == 15
        assert meta["distribution"]["THREAT_INTEL_ATTACK"] == 10

        citations = [p["citation"] for p in meta["research_papers"]]
        assert any("Lyastani" in c for c in citations)
        assert any("Wiefling" in c for c in citations)
        assert any("Kent" in c for c in citations)
        assert any("Bonneau" in c for c in citations)

    def test_benign_recovery_cohort_has_zero_false_positives(self):
        """
        Tests Cohort 2 (Sir's Scenario / Wiefling et al.):
        User fails/forgets passkey and logs in via password on their own system and IP.
        Expected:
        - 100% of recovery journeys identified as recovery candidates.
        - Exactly 0 false positive drift alerts (FPR = 0.0%).
        """
        recovery_events = [
            e for e in self.dataset["events"]
            if "recov" in e["userId"]
        ]
        result = self.pipeline.process_raw_events(recovery_events, provider="keycloak")
        assert len(result.journeys) == 15
        assert len(result.alerts) == 15

        for alert in result.alerts:
            # 1. Recovery candidate classified
            assert alert.is_recovery_candidate is True
            assert alert.context_evidence.is_recovery_candidate is True

            # 2. No false drift alert
            assert alert.drift_detected is False
            assert alert.alert_type == "INFORMATIONAL"
            assert alert.is_actionable is False
            assert alert.risk_assessment.score == 0
            assert alert.risk_assessment.severity == RiskSeverity.LOW

    def test_adversarial_drift_cohort_has_perfect_recall(self):
        """
        Tests Cohort 3 (Lyastani et al. S&P 2020 downgrade attacks):
        Passkey fails on corporate device -> password success from unfamiliar device / foreign IP.
        Expected:
        - 100% of adversarial drift attacks detected (Recall = 100.0%).
        - Elevated risk score (>= 70) and HIGH or CRITICAL severity.
        """
        drift_events = [
            e for e in self.dataset["events"]
            if "drift" in e["userId"]
        ]
        result = self.pipeline.process_raw_events(drift_events, provider="keycloak")
        assert len(result.journeys) == 15
        assert len(result.alerts) == 15

        for alert in result.alerts:
            assert alert.drift_detected is True
            assert alert.alert_type == "ASSURANCE_DRIFT"
            assert alert.is_recovery_candidate is False
            assert alert.context_evidence.is_new_device is True
            assert alert.risk_assessment.score >= 70
            assert alert.risk_assessment.severity in [RiskSeverity.HIGH, RiskSeverity.CRITICAL]

    def test_threat_intelligence_cohort_escalation(self):
        """
        Tests Cohort 4 (Malicious IP detection):
        Events originating from known malicious AbuseIPDB nodes.
        Expected:
        - IP reputation flagged as KNOWN_MALICIOUS.
        - Operational priority escalated to HIGH_PRIORITY.
        """
        threat_events = [
            e for e in self.dataset["events"]
            if "threat" in e["userId"]
        ]
        result = self.pipeline.process_raw_events(threat_events, provider="keycloak")
        assert len(result.journeys) == 10

        for alert in result.alerts:
            assert alert.ip_reputation is not None
            assert alert.ip_reputation.status == STATUS_KNOWN_MALICIOUS
            assert alert.priority == AlertPriority.HIGH_PRIORITY

    def test_end_to_end_benchmark_full_dataset(self):
        """
        Processes entire 100-journey dataset through the pipeline and verifies summary metrics.
        """
        result = self.pipeline.process_raw_events(self.dataset["events"], provider="keycloak")
        assert result.total_raw_events == len(self.dataset["events"])
        assert len(result.journeys) == 100
        assert len(result.alerts) == 100

        # Benchmark verification calculations
        alert_map = {a.user_id: a for a in result.alerts}
        gt = self.dataset["ground_truth"]

        # 1. Benign recovery: 0 false positive drift alerts
        recov_users = [u for u, g in gt.items() if g["category"] == "BENIGN_RECOVERY"]
        recov_fp_drifts = sum(1 for u in recov_users if alert_map[u].drift_detected)
        recov_candidates = sum(1 for u in recov_users if alert_map[u].is_recovery_candidate)
        assert recov_candidates == len(recov_users)
        assert recov_fp_drifts == 0

        # 2. Adversarial drift: 100% recall
        drift_users = [u for u, g in gt.items() if g["category"] == "ADVERSARIAL_DRIFT"]
        drift_detected = sum(1 for u in drift_users if alert_map[u].drift_detected)
        assert drift_detected == len(drift_users)

