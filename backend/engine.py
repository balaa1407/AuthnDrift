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
        reputation_service: Optional[IPReputationService] = None
    ):
        self.assurance_model = assurance_model or AssuranceModel()
        self.drift_detector = drift_detector or DriftDetector(assurance_model=self.assurance_model)
        self.context_analyzer = context_analyzer or ContextAnalyzer()
        self.risk_engine = risk_engine or RiskEngine()
        self.alert_generator = alert_generator or AlertGenerator()
        self.reputation_service = reputation_service

    def evaluate_journey(
        self,
        journey: List[AuthenticationEvent],
        known_devices: Optional[Set[str]] = None,
        known_locations: Optional[Set[str]] = None,
        known_authenticators: Optional[Set[str]] = None,
        location_profiler: Optional[LocationProfiler] = None,
        user_profiles: Optional[Dict[str, UserLocationProfile]] = None,
        session_id: Optional[str] = None,
        reputation_service: Optional[IPReputationService] = None
    ) -> SecurityAlert:
        """
        Executes end-to-end security evaluation for an authentication journey:
        1. Drift Detection (Assurance comparison)
        2. Contextual Correlation (Per-user location profile & device baselines)
        3. Threat Intelligence Correlation (IP Reputation lookup)
        4. Risk Assessment
        5. Explainable Alert Generation
        """
        drift_result = self.drift_detector.detect_drift(journey)
        context_evidence = self.context_analyzer.analyze_journey_context(
            journey=journey,
            known_devices=known_devices,
            known_locations=known_locations,
            known_authenticators=known_authenticators,
            location_profiler=location_profiler,
            user_profiles=user_profiles
        )

        # 3. IP Threat Intelligence Correlation
        active_reputation = reputation_service or self.reputation_service
        if active_reputation and context_evidence.ip_address:
            try:
                context_evidence.ip_reputation = active_reputation.get_ip_reputation(context_evidence.ip_address)
            except Exception:
                context_evidence.ip_reputation = None

        # 3b. Legitimate Recovery Candidate Evaluation
        # If strong auth failed followed by weaker success on the SAME KNOWN device and SAME IP,
        # without contextual anomalies, classify as a legitimate recovery candidate.
        if (
            drift_result.drift_detected
            and drift_result.transition_type in (RULE_FAILED_STRONG_SUCCESS_WEAK, RULE_MULTI_FAILURE_FALLBACK)
            and context_evidence.is_new_device is False
            and not any(a.anomaly_type in ("DEVICE_CHANGE", "IP_CHANGE", "LOCATION_CHANGE") for a in context_evidence.context_anomalies)
            and context_evidence.is_location_changed is not True
            and context_evidence.authenticator_registered is not True
            and getattr(context_evidence.ip_reputation, "status", None) != "KNOWN_MALICIOUS"
        ):
            context_evidence.is_recovery_candidate = True
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
