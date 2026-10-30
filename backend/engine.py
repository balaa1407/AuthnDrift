"""
AuthDrift: Core Security and Detection Engine Facade.
Coordinates Assurance Assignment, Drift Detection, Contextual Correlation,
Risk Scoring, and Explainable Alert Generation.
"""

from typing import List, Optional, Set
from backend.models.event import AuthenticationEvent
from backend.models.detection import SecurityAlert
from backend.assurance.assurance_model import AssuranceModel
from backend.detection.drift_detector import DriftDetector
from backend.correlation.context_analyzer import ContextAnalyzer
from backend.risk.risk_engine import RiskEngine
from backend.alerts.alert_generator import AlertGenerator


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
        alert_generator: Optional[AlertGenerator] = None
    ):
        self.assurance_model = assurance_model or AssuranceModel()
        self.drift_detector = drift_detector or DriftDetector()
        self.context_analyzer = context_analyzer or ContextAnalyzer()
        self.risk_engine = risk_engine or RiskEngine()
        self.alert_generator = alert_generator or AlertGenerator()

    def evaluate_journey(
        self,
        journey: List[AuthenticationEvent],
        known_devices: Optional[Set[str]] = None,
        known_locations: Optional[Set[str]] = None,
        known_authenticators: Optional[Set[str]] = None,
        session_id: Optional[str] = None
    ) -> SecurityAlert:
        """
        Executes end-to-end security evaluation for an authentication journey:
        1. Drift Detection (Assurance comparison)
        2. Contextual Correlation
        3. Risk Assessment
        4. Explainable Alert Generation
        """
        drift_result = self.drift_detector.detect_drift(journey)
        context_evidence = self.context_analyzer.analyze_journey_context(
            journey=journey,
            known_devices=known_devices,
            known_locations=known_locations,
            known_authenticators=known_authenticators
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
