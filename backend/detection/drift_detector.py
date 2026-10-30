"""
AuthDrift: Core Drift Detection Engine.
Analyses reconstructed authentication journeys and flags assurance downgrades with supporting evidence.
"""

from datetime import datetime
from typing import List, Optional
from backend.models.event import AuthenticationEvent
from backend.models.detection import DriftResult
from backend.models.assurance import AssuranceLevel
from backend.assurance.assurance_assignment import assign_assurance
from backend.detection.detection_rules import (
    DriftDetectionConfig,
    RULE_DOWNGRADE_GENERAL,
    RULE_FAILED_STRONG_SUCCESS_WEAK,
    RULE_MULTI_FAILURE_FALLBACK,
    RULE_REPEATED_FAILURES_SAME_METHOD,
    RULE_STEP_UP_AUTHENTICATION
)


def _is_failure_outcome(outcome: Optional[str]) -> bool:
    """Helper to safely evaluate failure outcomes without crashing on None or non-string."""
    if not outcome:
        return False
    return str(outcome).strip().upper() in ["FAILURE", "FAILED", "ERROR"]


class DriftDetector:
    """
    Evaluates authentication journeys for assurance drift.
    """

    def __init__(self, config: Optional[DriftDetectionConfig] = None):
        self.config = config or DriftDetectionConfig()

    def detect_drift(self, journey: List[AuthenticationEvent]) -> DriftResult:
        """
        Analyzes a chronological authentication journey to identify assurance drift.
        Defensively sorts events chronologically to ensure robust evaluation.
        """
        if not journey or len(journey) < 2:
            return DriftResult(
                drift_detected=False,
                reason="Insufficient events in journey to detect drift (minimum 2 required)."
            )

        # Defensively ensure events are chronologically ordered
        sorted_journey = sorted(
            journey,
            key=lambda e: e.timestamp if e.timestamp else datetime.min
        )

        max_previous_event = sorted_journey[0]
        max_previous_assurance = assign_assurance(max_previous_event.authentication_method)
        has_prior_failure = _is_failure_outcome(max_previous_event.outcome)
        failure_count = 1 if has_prior_failure else 0

        for current_event in sorted_journey[1:]:
            current_assurance = assign_assurance(current_event.authentication_method)
            current_is_failure = _is_failure_outcome(current_event.outcome)

            if current_is_failure:
                failure_count += 1

            # Check for Assurance Downgrade
            assurance_drop = max_previous_assurance.value - current_assurance.value
            if assurance_drop >= self.config.min_assurance_drop:
                # Distinguish transition types
                if has_prior_failure and not current_is_failure:
                    transition_type = RULE_FAILED_STRONG_SUCCESS_WEAK
                    reason = (
                        f"Failed strong authentication ({max_previous_event.authentication_method} - {max_previous_assurance.name}) "
                        f"followed by successful fallback to lower-assurance method "
                        f"({current_event.authentication_method} - {current_assurance.name})."
                    )
                elif failure_count > 1:
                    transition_type = RULE_MULTI_FAILURE_FALLBACK
                    reason = (
                        f"Multiple failed authentication attempts ({failure_count}) followed by "
                        f"assurance downgrade from {max_previous_assurance.name} ({max_previous_event.authentication_method}) "
                        f"to {current_assurance.name} ({current_event.authentication_method})."
                    )
                else:
                    transition_type = RULE_DOWNGRADE_GENERAL
                    reason = (
                        f"Authentication assurance decreased from {max_previous_assurance.name} "
                        f"({max_previous_event.authentication_method}) to {current_assurance.name} "
                        f"({current_event.authentication_method})."
                    )

                return DriftResult(
                    drift_detected=True,
                    reason=reason,
                    previous_method=max_previous_event.authentication_method,
                    previous_assurance=max_previous_assurance,
                    current_method=current_event.authentication_method,
                    current_assurance=current_assurance,
                    transition_type=transition_type
                )

            # Update highest assurance if current is higher (step-up)
            if current_assurance.value > max_previous_assurance.value:
                max_previous_event = current_event
                max_previous_assurance = current_assurance

            if current_is_failure:
                has_prior_failure = True

        # Check if repeated failures occurred at the same tier
        if failure_count >= 2:
            return DriftResult(
                drift_detected=False,
                reason=f"Repeated authentication failures ({failure_count}) observed without assurance downgrade.",
                transition_type=RULE_REPEATED_FAILURES_SAME_METHOD
            )

        return DriftResult(
            drift_detected=False,
            reason="No assurance decrease detected in journey.",
            transition_type="NORMAL_JOURNEY"
        )
