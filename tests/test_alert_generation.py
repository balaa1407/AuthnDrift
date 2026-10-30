"""
Unit tests for AuthDrift Explainable Alert Generation (Objective 4).
"""

from datetime import datetime, timezone
import pytest
from backend.models.event import AuthenticationEvent
from backend.models.detection import (
    DriftResult,
    ContextEvidence,
    RiskAssessment,
    RiskSeverity,
    AlertPriority
)
from backend.models.assurance import AssuranceLevel
from backend.alerts.alert_generator import AlertGenerator


def make_event(method: str, outcome: str = "SUCCESS", user_id: str = "user-123"):
    return AuthenticationEvent(
        event_id="evt-1",
        user_id=user_id,
        timestamp=datetime.now(timezone.utc),
        event_type="LOGIN",
        authentication_method=method,
        outcome=outcome
    )


class TestAlertGenerator:
    def setup_method(self):
        self.generator = AlertGenerator()

    def test_alert_structure_and_explanation(self):
        journey = [
            make_event("passkey", "FAILURE"),
            make_event("password", "SUCCESS")
        ]
        drift = DriftResult(
            drift_detected=True,
            reason="Failed strong authentication (passkey - HIGH) followed by successful fallback (password - LOW).",
            previous_method="passkey",
            previous_assurance=AssuranceLevel.HIGH,
            current_method="password",
            current_assurance=AssuranceLevel.LOW
        )
        context = ContextEvidence(
            is_new_device=True,
            device_id="iphone-15-pro"
        )
        risk = RiskAssessment(
            score=75,
            severity=RiskSeverity.HIGH,
            triggered_factors=["Assurance Downgrade (HIGH -> LOW)", "New Device Detected"],
            rationale="Assessed as HIGH risk (Score 75/100)."
        )

        alert = self.generator.generate_alert(journey, drift, context, risk)

        assert alert.alert_id.startswith("alert-")
        assert alert.user_id == "user-123"
        assert alert.drift_detected is True
        assert alert.is_actionable is True
        assert alert.priority == AlertPriority.HIGH_PRIORITY.value
        assert "iphone-15-pro" in alert.explanation
        assert "passkey" in alert.explanation.lower()
        assert "password" in alert.explanation.lower()
        # Must include legitimate recovery notice
        assert "not definitive proof" in alert.explanation

    def test_alert_omits_unpresent_context(self):
        # When device/location is None, alert must NOT claim a new device or location
        journey = [make_event("passkey")]
        drift = DriftResult(drift_detected=False, reason="No drift")
        context = ContextEvidence(is_new_device=None, is_location_changed=None)
        risk = RiskAssessment(score=0, severity=RiskSeverity.LOW, rationale="Normal")

        alert = self.generator.generate_alert(journey, drift, context, risk)
        assert alert.priority == AlertPriority.INFORMATIONAL.value
        assert "new device" not in alert.explanation.lower()
        assert "location changed" not in alert.explanation.lower()

    def test_alert_chronological_method_ordering(self):
        # Defect regression: Ensure methods in narrative are ordered chronologically without set scrambling
        journey = [
            make_event("passkey", "FAILURE"),
            make_event("totp", "FAILURE"),
            make_event("password", "SUCCESS")
        ]
        drift = DriftResult(
            drift_detected=True,
            reason="Multiple failures fallback",
            previous_method="passkey",
            current_method="password"
        )
        context = ContextEvidence()
        risk = RiskAssessment(score=60, severity=RiskSeverity.HIGH)

        alert = self.generator.generate_alert(journey, drift, context, risk)
        assert "passkey, totp, password" in alert.explanation

    def test_alert_priority_tiers(self):
        journey = [make_event("passkey")]
        drift_no = DriftResult(drift_detected=False, reason="No drift")
        drift_yes = DriftResult(drift_detected=True, reason="Drift occurred")

        # 1. Informational: no drift, low score
        alert_info = self.generator.generate_alert(
            journey, drift_no, ContextEvidence(), RiskAssessment(score=10, severity=RiskSeverity.LOW)
        )
        assert alert_info.priority == AlertPriority.INFORMATIONAL.value
        assert alert_info.is_actionable is False

        # 2. Investigation Required: drift detected with moderate score
        alert_investigate = self.generator.generate_alert(
            journey, drift_yes, ContextEvidence(), RiskAssessment(score=40, severity=RiskSeverity.MEDIUM)
        )
        assert alert_investigate.priority == AlertPriority.INVESTIGATION_REQUIRED.value
        assert alert_investigate.is_actionable is True

        # 3. High Priority: high score or critical persistent signal
        alert_high = self.generator.generate_alert(
            journey, drift_yes, ContextEvidence(), RiskAssessment(score=80, severity=RiskSeverity.CRITICAL)
        )
        assert alert_high.priority == AlertPriority.HIGH_PRIORITY.value
        assert alert_high.is_actionable is True
