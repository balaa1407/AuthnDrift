"""
AuthDrift: Core Security and Detection Engine Facade.
Coordinates Assurance Assignment, Drift Detection, Contextual Correlation,
IP Threat Intelligence, Risk Scoring, and Explainable Alert Generation.
"""

from typing import Any, Dict, List, Optional, Set, Tuple
from backend.models.event import AuthenticationEvent
from backend.models.detection import ContextEvidence, DriftResult, SecurityAlert
from backend.assurance.assurance_model import AssuranceModel
from backend.detection.drift_detector import DriftDetector
from backend.correlation.context_analyzer import ContextAnalyzer, _is_same_subnet, _is_valid_ip
from backend.correlation.location_profiler import LocationProfiler, UserLocationProfile
from backend.risk.risk_engine import RiskEngine
from backend.alerts.alert_generator import AlertGenerator
from backend.threat_intelligence.reputation_service import IPReputationService
from backend.detection.detection_rules import RULE_FAILED_STRONG_SUCCESS_WEAK


class AuthDriftEngine:
    """
    Unified entry point for the deterministic security intelligence layer.
    """

    def __init__(
        self,
        assurance_model: Optional[AssuranceModel] = None,
        drift_detector: Optional[DriftDetector] = None,
        context_analyzer: Optional[ContextAnalyzer] = None,
        risk_engine: Optional[RiskEngine] = None,
        alert_generator: Optional[AlertGenerator] = None,
        reputation_service: Optional[IPReputationService] = None,
        user_baselines: Optional[Dict[str, Dict[str, Any]]] = None,
    ):
        self.assurance_model = assurance_model or AssuranceModel()
        self.drift_detector = drift_detector or DriftDetector(assurance_model=self.assurance_model)
        self.context_analyzer = context_analyzer or ContextAnalyzer()
        self.risk_engine = risk_engine or RiskEngine()
        self.alert_generator = alert_generator or AlertGenerator()
        self.reputation_service = reputation_service
        self.user_baselines: Dict[str, Dict[str, Any]] = dict(user_baselines or {})

    @staticmethod
    def _has_verified_ip_continuity(
        journey: List[AuthenticationEvent],
        context_evidence: ContextEvidence,
    ) -> bool:
        """
        Verifies IP continuity for recovery eligibility:
        - True if an established per-user IP baseline matched.
        - False if an IP baseline mismatched or invalid/missing IP.
        - When no explicit IP baseline is configured (is_primary_ip_matched is None),
          requires >= 2 valid observed IP events in the journey sharing exact IP or /24 (/64) subnet.
        """
        if context_evidence.is_primary_ip_matched is True:
            return True
        if context_evidence.is_primary_ip_matched is False:
            return False

        valid_ips = [e.ip_address for e in journey if _is_valid_ip(e.ip_address)]
        if len(valid_ips) < 2:
            return False
        anchor_ip = valid_ips[0]
        return all(
            ip == anchor_ip or _is_same_subnet(anchor_ip, ip) is True
            for ip in valid_ips[1:]
        )

    @classmethod
    def _classify_journey_outcome(
        cls,
        journey: List[AuthenticationEvent],
        drift_result: DriftResult,
        context_evidence: ContextEvidence,
    ) -> Tuple[str, str, bool]:
        """
        Deterministically classifies journey case category (CASE_1..CASE_5 / ROUTINE)
        and ACCP recovery eligibility strictly from empirical journey telemetry.
        Independent high-risk signals or missing context always fail closed.
        """
        if context_evidence.authenticator_registered is True:
            return ("CASE_5_ROGUE_AUTHENTICATOR_REGISTRATION", "CRITICAL_SECURITY_EVENT", False)

        has_device = context_evidence.device_id is not None
        has_ip = _is_valid_ip(context_evidence.ip_address)
        ip_rep_status = getattr(getattr(context_evidence, "ip_reputation", None), "status", None)
        has_threat_intel_anomaly = ip_rep_status in ("KNOWN_MALICIOUS", "SUSPICIOUS")
        has_location_anomaly = (
            context_evidence.is_location_changed is True
            or any(getattr(a, "is_impossible_travel", False) for a in context_evidence.context_anomalies)
        )
        has_ip_anomaly = any(
            a.anomaly_type == "IP_CHANGE" and not getattr(a, "subnet_continuity", False)
            for a in context_evidence.context_anomalies
        )
        has_device_anomaly = (
            context_evidence.is_new_device is True
            or any(a.anomaly_type == "DEVICE_CHANGE" for a in context_evidence.context_anomalies)
        )
        has_hardware_or_network_change = has_device_anomaly or has_ip_anomaly

        # Non-drift journeys (including threat-intel or contextual-only anomalies)
        if not drift_result.drift_detected and context_evidence.prior_failures_count == 0:
            if has_threat_intel_anomaly:
                return ("THREAT_INTEL_MATCH", "CONTEXTUAL_ANOMALY", False)
            if has_device_anomaly:
                return ("CASE_2_DIFF_DEVICE_SAME_IP", "SUSPICIOUS_DEVICE_CHANGE", False)
            if has_ip_anomaly or has_location_anomaly:
                return ("CASE_3_SAME_DEVICE_DIFF_IP", "CONTEXTUAL_NETWORK_ANOMALY", False)
            if not has_device or not has_ip:
                return ("UNCERTAIN_MISSING_CONTEXT", "UNCERTAIN_MISSING_CONTEXT", False)
            return ("ROUTINE", "ROUTINE_AUTHENTICATION", False)

        if not has_device and not has_ip:
            return ("UNCERTAIN_MISSING_CONTEXT", "UNCERTAIN_MISSING_CONTEXT", False)

        dev_matched = context_evidence.is_primary_device_matched
        ip_matched = context_evidence.is_primary_ip_matched
        ip_continuity_verified = cls._has_verified_ip_continuity(journey, context_evidence)

        # Case 1: Benign single fallback after strong auth failure on verified same device & IP/subnet
        if (
            drift_result.drift_detected
            and drift_result.transition_type == RULE_FAILED_STRONG_SUCCESS_WEAK
            and context_evidence.prior_failures_count == 1
            and dev_matched is True
            and context_evidence.is_new_device is False
            and ip_continuity_verified
            and has_device
            and has_ip
            and not has_threat_intel_anomaly
            and not has_location_anomaly
            and not has_hardware_or_network_change
        ):
            return ("CASE_1_SAME_DEVICE_SAME_IP", "GENUINE_RECOVERY", True)

        if not drift_result.drift_detected:
            if has_threat_intel_anomaly:
                return ("THREAT_INTEL_MATCH", "CONTEXTUAL_ANOMALY", False)
            if dev_matched is False or has_device_anomaly:
                return ("CASE_2_DIFF_DEVICE_SAME_IP", "SUSPICIOUS_DEVICE_CHANGE", False)
            if ip_matched is False or has_ip_anomaly or has_location_anomaly:
                return ("CASE_3_SAME_DEVICE_DIFF_IP", "CONTEXTUAL_NETWORK_ANOMALY", False)
            if not has_device or not has_ip:
                return ("UNCERTAIN_MISSING_CONTEXT", "UNCERTAIN_MISSING_CONTEXT", False)
            return ("ROUTINE", "ROUTINE_AUTHENTICATION", False)

        # Drift detected transitions
        if dev_matched is False and ip_matched is True:
            return ("CASE_2_DIFF_DEVICE_SAME_IP", "SUSPICIOUS_DEVICE_CHANGE", False)

        if dev_matched is True and (ip_matched is False or has_ip_anomaly):
            return ("CASE_3_SAME_DEVICE_DIFF_IP", "CONTEXTUAL_NETWORK_ANOMALY", False)

        if dev_matched is False and (ip_matched is False or has_ip_anomaly):
            return ("CASE_4_DIFF_DEVICE_DIFF_IP", "ADVERSARIAL_DRIFT", False)

        if dev_matched is False:
            return ("ADVERSARIAL_DRIFT_NEW_DEVICE", "ADVERSARIAL_DRIFT", False)

        return ("UNCERTAIN_MISSING_CONTEXT", "UNCERTAIN_MISSING_CONTEXT", False)

    def evaluate_journey(
        self,
        journey: List[AuthenticationEvent],
        known_devices: Optional[Set[str]] = None,
        known_locations: Optional[Set[str]] = None,
        known_authenticators: Optional[Set[str]] = None,
        known_ips: Optional[Set[str]] = None,
        primary_device: Optional[str] = None,
        primary_ip: Optional[str] = None,
        location_profiler: Optional[LocationProfiler] = None,
        user_profiles: Optional[Dict[str, UserLocationProfile]] = None,
        session_id: Optional[str] = None,
        reputation_service: Optional[IPReputationService] = None,
        user_baselines: Optional[Dict[str, Dict[str, Any]]] = None,
    ) -> SecurityAlert:
        """
        Executes end-to-end deterministic security evaluation for an authentication journey:
        1. Drift Detection (Assurance comparison)
        2. Contextual Correlation (Per-user location profile & isolated device/IP baselines)
        3. Threat Intelligence Correlation (IP Reputation lookup)
        4. Verified Recovery & Case Classification (Client continuity: Device, IP/Subnet)
        5. Risk Assessment
        6. Explainable Alert Generation
        """
        drift_result = self.drift_detector.detect_drift(journey)
        active_baselines = user_baselines if user_baselines is not None else (self.user_baselines or None)

        context_evidence = self.context_analyzer.analyze_journey_context(
            journey=journey,
            known_devices=known_devices,
            known_locations=known_locations,
            known_authenticators=known_authenticators,
            known_ips=known_ips,
            primary_device=primary_device,
            primary_ip=primary_ip,
            location_profiler=location_profiler,
            user_profiles=user_profiles,
            user_baselines=active_baselines,
        )

        # 3. IP Threat Intelligence Correlation
        active_reputation = reputation_service or self.reputation_service
        if active_reputation and context_evidence.ip_address:
            try:
                context_evidence.ip_reputation = active_reputation.get_ip_reputation(context_evidence.ip_address)
            except Exception:
                context_evidence.ip_reputation = None

        # 4. Deterministic Case Classification & ACCP Recovery Evaluation
        case_category, recovery_classification, is_recovery_candidate = self._classify_journey_outcome(
            journey=journey,
            drift_result=drift_result,
            context_evidence=context_evidence,
        )
        context_evidence.case_category = case_category
        context_evidence.recovery_classification = recovery_classification
        if is_recovery_candidate:
            context_evidence.is_recovery_candidate = True
            context_evidence.evidence_notes.append(
                "Legitimate authentication recovery candidate on verified known device and matching IP/subnet (ACCP)."
            )

        risk_assessment = self.risk_engine.evaluate_risk(drift_result, context_evidence)
        alert = self.alert_generator.generate_alert(
            journey=journey,
            drift_result=drift_result,
            context_evidence=context_evidence,
            risk_assessment=risk_assessment,
            session_id=session_id
        )
        return alert
