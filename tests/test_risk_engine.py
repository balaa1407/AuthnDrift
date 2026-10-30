"""
Unit tests for AuthDrift Risk Scoring Engine (Objective 4).
"""

import pytest
from backend.models.detection import DriftResult, ContextEvidence, RiskSeverity
from backend.models.assurance import AssuranceLevel
from backend.risk.risk_config import RiskEngineConfig
from backend.risk.risk_engine import RiskEngine
from backend.detection.detection_rules import (
    RULE_FAILED_STRONG_SUCCESS_WEAK,
    RULE_MULTI_FAILURE_FALLBACK
)


class TestRiskEngine:
    def setup_method(self):
        self.config = RiskEngineConfig()
        self.engine = RiskEngine(self.config)

    def test_normal_journey_zero_risk(self):
        drift = DriftResult(drift_detected=False, reason="No drift")
        context = ContextEvidence()
        assessment = self.engine.evaluate_risk(drift, context)

        assert assessment.score == 0
        assert assessment.severity == RiskSeverity.LOW
        assert len(assessment.triggered_factors) == 0

    def test_high_to_low_downgrade_scoring(self):
        drift = DriftResult(
            drift_detected=True,
            reason="Authentication assurance decreased from HIGH to LOW",
            previous_assurance=AssuranceLevel.HIGH,
            current_assurance=AssuranceLevel.LOW
        )
        context = ContextEvidence()
        assessment = self.engine.evaluate_risk(drift, context)

        # Base downgrade weight is 40 -> MEDIUM severity
        assert assessment.score == 40
        assert assessment.severity == RiskSeverity.MEDIUM
        assert "Assurance Downgrade (HIGH -> LOW)" in assessment.triggered_factors

    def test_compound_risk_with_new_device_and_failures(self):
        # Scenario: Failed passkey, password success from new device
        drift = DriftResult(
            drift_detected=True,
            reason="Failed strong authentication (passkey - HIGH) followed by successful fallback (password - LOW).",
            previous_assurance=AssuranceLevel.HIGH,
            current_assurance=AssuranceLevel.LOW,
            transition_type=RULE_FAILED_STRONG_SUCCESS_WEAK
        )
        context = ContextEvidence(
            is_new_device=True,
            device_id="unfamiliar-phone-9",
            prior_failures_count=2
        )
        assessment = self.engine.evaluate_risk(drift, context)

        # 40 (high->low) + 15 (failed strong) + 10 (repeated failures) + 20 (new device) = 85 -> CRITICAL
        assert assessment.score == 85
        assert assessment.severity == RiskSeverity.CRITICAL
        assert len(assessment.triggered_factors) == 4

    def test_authenticator_registration_post_downgrade(self):
        # Authenticator added post downgrade is a major persistence indicator
        drift = DriftResult(
            drift_detected=True,
            reason="Authentication assurance decreased from HIGH to LOW",
            previous_assurance=AssuranceLevel.HIGH,
            current_assurance=AssuranceLevel.LOW
        )
        context = ContextEvidence(
            authenticator_registered=True,
            authenticator_id="malicious-yubikey-888"
        )
        assessment = self.engine.evaluate_risk(drift, context)

        # 40 + 25 = 65 -> HIGH
        assert assessment.score == 65
        assert assessment.severity == RiskSeverity.HIGH
        assert "New Authenticator Registered During Journey" in assessment.triggered_factors

    def test_score_capped_at_100(self):
        drift = DriftResult(
            drift_detected=True,
            reason="Failed strong authentication",
            previous_assurance=AssuranceLevel.HIGH,
            current_assurance=AssuranceLevel.LOW,
            transition_type=RULE_FAILED_STRONG_SUCCESS_WEAK
        )
        context = ContextEvidence(
            is_new_device=True,
            is_location_changed=True,
            authenticator_registered=True,
            prior_failures_count=5
        )
        assessment = self.engine.evaluate_risk(drift, context)
        # Sum would be 40 + 15 + 10 + 20 + 15 + 25 = 125, capped at 100
        assert assessment.score == 100
        assert assessment.severity == RiskSeverity.CRITICAL

    def test_multi_failure_fallback_triggers_strong_failure_factor(self):
        # Defect regression: machine-readable RULE_MULTI_FAILURE_FALLBACK must trigger Factor 2
        drift = DriftResult(
            drift_detected=True,
            reason="Multiple failed authentication attempts (2) followed by assurance downgrade from HIGH (passkey) to LOW (password).",
            previous_assurance=AssuranceLevel.HIGH,
            current_assurance=AssuranceLevel.LOW,
            transition_type=RULE_MULTI_FAILURE_FALLBACK
        )
        context = ContextEvidence(prior_failures_count=2)
        assessment = self.engine.evaluate_risk(drift, context)
        # 40 (high->low) + 15 (failed strong fallback) + 10 (repeated failures) = 65 -> HIGH
        assert assessment.score == 65
        assert "Failed Strong Method Prior to Fallback" in assessment.triggered_factors
        assert len(assessment.triggered_factors) == 3
