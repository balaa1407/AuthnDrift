"""
AuthDrift: Risk Scoring Engine.
Computes transparent, reproducible, non-duplicative risk scores based on
drift results and contextual evidence.

Mathematical Scoring Approach:
The risk score S in [0, 100] is computed as an additive heuristic:
    S = min(100, max(0, sum(w_i * 1_{factor_i})))

Academic & Operational Disclaimer:
This risk score is a deterministic, rule-based engineering heuristic calibrated
for explainable security monitoring and SIEM alert prioritization. It represents
relative suspiciousness across multi-step journeys, not a statistically calibrated
probability of malicious compromise.
"""

from typing import Dict, List, Optional
from backend.models.detection import DriftResult, ContextEvidence, RiskAssessment, RiskSeverity
from backend.models.assurance import AssuranceLevel
from backend.risk.risk_config import RiskEngineConfig
from backend.detection.detection_rules import (
    RULE_FAILED_STRONG_SUCCESS_WEAK,
    RULE_MULTI_FAILURE_FALLBACK
)


class RiskEngine:
    """
    Calculates risk assessments using documented, configurable rules.
    """

    def __init__(self, config: Optional[RiskEngineConfig] = None):
        self.config = config or RiskEngineConfig()

    def evaluate_risk(
        self,
        drift_result: DriftResult,
        context_evidence: ContextEvidence
    ) -> RiskAssessment:
        score = 0
        triggered_factors: List[str] = []
        breakdown: Dict[str, int] = {}

        # Factor 1: Assurance Downgrade
        if drift_result.drift_detected and drift_result.previous_assurance and drift_result.current_assurance:
            prev = drift_result.previous_assurance
            curr = drift_result.current_assurance

            if prev == AssuranceLevel.HIGH and curr == AssuranceLevel.LOW:
                pts = self.config.weight_downgrade_high_to_low
                score += pts
                factor_name = "Assurance Downgrade (HIGH -> LOW)"
                triggered_factors.append(factor_name)
                breakdown[factor_name] = pts
            elif prev == AssuranceLevel.HIGH and curr == AssuranceLevel.MEDIUM:
                pts = self.config.weight_downgrade_high_to_medium
                score += pts
                factor_name = "Assurance Downgrade (HIGH -> MEDIUM)"
                triggered_factors.append(factor_name)
                breakdown[factor_name] = pts
            elif prev == AssuranceLevel.MEDIUM and curr == AssuranceLevel.LOW:
                pts = self.config.weight_downgrade_medium_to_low
                score += pts
                factor_name = "Assurance Downgrade (MEDIUM -> LOW)"
                triggered_factors.append(factor_name)
                breakdown[factor_name] = pts

        # Factor 2: Preceding Strong Authentication Failure
        # Triggered when strong authentication failed prior to fallback/downgrade
        has_failed_strong = (
            drift_result.transition_type == RULE_FAILED_STRONG_SUCCESS_WEAK
            or (
                drift_result.transition_type == RULE_MULTI_FAILURE_FALLBACK
                and drift_result.previous_assurance == AssuranceLevel.HIGH
            )
            or ("Failed strong authentication" in (drift_result.reason or ""))
        )

        if has_failed_strong:
            pts = self.config.weight_failed_strong_preceding
            score += pts
            factor_name = "Failed Strong Method Prior to Fallback"
            triggered_factors.append(factor_name)
            breakdown[factor_name] = pts

        # Factor 3: Repeated Failures (>= 2 attempts)
        if context_evidence.prior_failures_count >= 2:
            pts = self.config.weight_repeated_failures
            score += pts
            factor_name = f"Repeated Failures ({context_evidence.prior_failures_count} attempts)"
            triggered_factors.append(factor_name)
            breakdown[factor_name] = pts

        # Factor 4: New Device (only applied if confirmed new, not None or False)
        if context_evidence.is_new_device is True:
            pts = self.config.weight_new_device
            score += pts
            factor_name = f"New Device Detected ({context_evidence.device_id or 'unknown'})"
            triggered_factors.append(factor_name)
            breakdown[factor_name] = pts

        # Factor 5: Location Change (only applied if confirmed changed, not None or False)
        if context_evidence.is_location_changed is True:
            pts = self.config.weight_location_change
            score += pts
            factor_name = f"Changed Location ({context_evidence.location or 'unknown'})"
            triggered_factors.append(factor_name)
            breakdown[factor_name] = pts

        # Factor 6: New Authenticator Registered During Journey
        if context_evidence.authenticator_registered is True:
            pts = self.config.weight_authenticator_registered
            score += pts
            factor_name = "New Authenticator Registered During Journey"
            triggered_factors.append(factor_name)
            breakdown[factor_name] = pts

        # Cap score between 0 and 100
        final_score = min(100, max(0, score))
        severity = self.config.get_severity(final_score)

        if not triggered_factors:
            rationale = "Normal authentication journey with no anomalous degradation or suspicious context."
        else:
            rationale = (
                f"Assessed as {severity.value} risk (Score {final_score}/100) based on {len(triggered_factors)} "
                f"correlated factor(s): {', '.join(triggered_factors)}."
            )

        return RiskAssessment(
            score=final_score,
            severity=severity,
            triggered_factors=triggered_factors,
            factor_breakdown=breakdown,
            rationale=rationale
        )
