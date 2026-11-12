"""
AuthDrift: Core Security and Detection Engine Facade.
Coordinates Assurance Assignment, Drift Detection, Contextual Correlation,
IP Threat Intelligence, Risk Scoring, and Explainable Alert Generation.
"""

from typing import Dict, List, Optional, Set
from backend.models.event import AuthenticationEvent
from backend.models.detection import SecurityAlert
from backend.assurance.assurance_model import AssuranceModel
from backend.detection.drift_detector import DriftDetector
from backend.correlation.context_analyzer import ContextAnalyzer
from backend.correlation.location_profiler import LocationProfiler, UserLocationProfile
from backend.risk.risk_engine import RiskEngine
from backend.alerts.alert_generator import AlertGenerator
from backend.threat_intelligence.reputation_service import IPReputationService
from backend.llm_calibration.fallback_memory import FallbackMemoryStore
from backend.llm_calibration.calibrator import LLMCalibrator
from backend.detection.detection_rules import (
    RULE_FAILED_STRONG_SUCCESS_WEAK,
    RULE_MULTI_FAILURE_FALLBACK
)


class AuthDriftEngine:
    """
    Unified entry point for the security intelligence layer.
    """

    def __init__(
        self,
        assurance_model: Optional[AssuranceModel] = None,
        drift_detector: Optional[DriftDetector] = None,
        context_analyzer: Optional[ContextAnalyzer] = None,
        risk_engine: Optional[RiskEngine] = None,
        alert_generator: Optional[AlertGenerator] = None,
        reputation_service: Optional[IPReputationService] = None,
        fallback_memory: Optional[FallbackMemoryStore] = None,
        calibrator: Optional[LLMCalibrator] = None
    ):
        self.assurance_model = assurance_model or AssuranceModel()
        self.drift_detector = drift_detector or DriftDetector(assurance_model=self.assurance_model)
        self.context_analyzer = context_analyzer or ContextAnalyzer()
        self.risk_engine = risk_engine or RiskEngine()
        self.alert_generator = alert_generator or AlertGenerator()
        self.reputation_service = reputation_service
        self.fallback_memory = fallback_memory or FallbackMemoryStore()
        self.calibrator = calibrator or LLMCalibrator(memory_store=self.fallback_memory)

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
        fallback_memory: Optional[FallbackMemoryStore] = None
    ) -> SecurityAlert:
        """
        Executes end-to-end security evaluation for an authentication journey:
        1. Drift Detection (Assurance comparison)
        2. Contextual Correlation (Per-user location profile & device baselines)
        3. Threat Intelligence Correlation (IP Reputation lookup)
        4. Verified Recovery & LLM Calibration (Client continuity: Person, Primary Device, Primary IP)
        5. Risk Assessment
        6. Explainable Alert Generation
        """
        drift_result = self.drift_detector.detect_drift(journey)
        active_memory = fallback_memory or self.fallback_memory

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
            fallback_memory=active_memory
        )

        # 3. IP Threat Intelligence Correlation
        active_reputation = reputation_service or self.reputation_service
        if active_reputation and context_evidence.ip_address:
            try:
                context_evidence.ip_reputation = active_reputation.get_ip_reputation(context_evidence.ip_address)
            except Exception:
                context_evidence.ip_reputation = None

        # 4. Verified Recovery Classification & Calibration (Client Continuity: Person, Primary Device, Primary IP)
        user_id = journey[0].user_id if journey else "unknown_user"
        u_profile = active_memory.get_profile(user_id) if active_memory else None

        calib_res = self.calibrator.calibrate_journey(
            journey=journey,
            drift_result=drift_result,
            context_evidence=context_evidence,
            user_profile=u_profile
        )

        context_evidence.recovery_classification = calib_res.classification
        context_evidence.case_category = calib_res.case_category

        if (
            calib_res.classification == "GENUINE_RECOVERY"
            and calib_res.is_drift_alert_suppressed
            and drift_result.drift_detected
            and drift_result.transition_type in (RULE_FAILED_STRONG_SUCCESS_WEAK, RULE_MULTI_FAILURE_FALLBACK)
        ):
            context_evidence.is_recovery_candidate = True
            context_evidence.evidence_notes.append(calib_res.reasoning)
        elif (
            drift_result.drift_detected
            and drift_result.transition_type in (RULE_FAILED_STRONG_SUCCESS_WEAK, RULE_MULTI_FAILURE_FALLBACK)
            and context_evidence.is_new_device is False
            and context_evidence.device_id is not None
            and context_evidence.ip_address is not None
            and not any(a.anomaly_type in ("DEVICE_CHANGE", "IP_CHANGE", "LOCATION_CHANGE") for a in context_evidence.context_anomalies)
            and context_evidence.is_location_changed is not True
            and context_evidence.authenticator_registered is not True
            and getattr(context_evidence.ip_reputation, "status", None) != "KNOWN_MALICIOUS"
        ):
            context_evidence.is_recovery_candidate = True
            context_evidence.case_category = "CASE_1_SAME_DEVICE_SAME_IP"
            context_evidence.recovery_classification = "GENUINE_RECOVERY"
            context_evidence.evidence_notes.append(
                "Legitimate authentication recovery candidate on verified known device and matching IP address."
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
