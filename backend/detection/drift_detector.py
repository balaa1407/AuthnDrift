"""
AuthDrift: Core Drift Detection Engine.
Analyses reconstructed authentication journeys and flags assurance downgrades with supporting evidence.
"""

from datetime import datetime
from typing import List, Optional, Set
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

# Lifecycle events that represent credential management or session control,
# not direct authentication challenges. These participate in contextual correlation, not drift detection.
LIFECYCLE_EVENT_TYPES: Set[str] = {
    "REGISTER_AUTHENTICATOR",
    "UPDATE_CREDENTIAL",
    "DELETE_CREDENTIAL",
    "CREDENTIAL_REGISTER",
    "LOGOUT",
    "SESSION_LOGOUT",
}


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
        Defensively sorts events, deduplicates log replays, and isolates lifecycle events.
        """
        if not journey or len(journey) < 2:
            return DriftResult(
                drift_detected=False,
                reason="Insufficient events in journey to detect drift (minimum 2 required)."
            )

        # 1. Defensively ensure events are chronologically ordered
        sorted_journey = sorted(
            journey,
            key=lambda e: e.timestamp if e.timestamp else datetime.min
        )

        # 2. Deduplicate repeated events by event_id to prevent log-replay artifacting
        deduped_journey: List[AuthenticationEvent] = []
        seen_ids: Set[str] = set()
        for event in sorted_journey:
            if event.event_id and event.event_id in seen_ids:
                continue
            if event.event_id:
                seen_ids.add(event.event_id)
            deduped_journey.append(event)

        # 3. Filter out non-authentication lifecycle events (e.g. authenticator registration)
        auth_events = [
            e for e in deduped_journey
            if str(e.event_type or "").strip().upper() not in LIFECYCLE_EVENT_TYPES
        ]

        if len(auth_events) < 2:
            return DriftResult(
                drift_detected=False,
                reason="Insufficient authentication events in journey to detect drift (minimum 2 required)."
            )

        max_previous_event = auth_events[0]
        max_previous_assurance = assign_assurance(max_previous_event.authentication_method)
        has_prior_failure = _is_failure_outcome(max_previous_event.outcome)
        failure_count = 1 if has_prior_failure else 0
        step_up_observed = False

        # Track failed events to ensure failed strong method verification
        failed_events: List[AuthenticationEvent] = []
        if has_prior_failure:
            failed_events.append(max_previous_event)

        for current_event in auth_events[1:]:
            current_assurance = assign_assurance(current_event.authentication_method)
            current_is_failure = _is_failure_outcome(current_event.outcome)

            if current_is_failure:
                failure_count += 1
                failed_events.append(current_event)

            # Check for Step-Up Authentication
            if current_assurance.value > max_previous_assurance.value:
                step_up_observed = True
                max_previous_event = current_event
                max_previous_assurance = current_assurance
                continue

            # Check for Assurance Downgrade
            assurance_drop = max_previous_assurance.value - current_assurance.value
            if assurance_drop >= self.config.min_assurance_drop:
                # Identify if any prior failed event had higher assurance than the current method
                stronger_failed_events = [
                    f for f in failed_events
                    if assign_assurance(f.authentication_method).value > current_assurance.value
                ]

                # If require_prior_failure is configured, do not flag drift unless a stronger method failed
                if self.config.require_prior_failure and not stronger_failed_events:
                    continue

                if failure_count > 1:
                    transition_type = RULE_MULTI_FAILURE_FALLBACK
                    reason = (
                        f"Multiple failed authentication attempts ({failure_count}) followed by "
                        f"assurance downgrade from {max_previous_assurance.name} ({max_previous_event.authentication_method}) "
                        f"to {current_assurance.name} ({current_event.authentication_method})."
                    )
                elif stronger_failed_events and not current_is_failure:
                    transition_type = RULE_FAILED_STRONG_SUCCESS_WEAK
                    failed_ref = stronger_failed_events[-1]
                    failed_ref_assurance = assign_assurance(failed_ref.authentication_method)
                    reason = (
                        f"Failed strong authentication ({failed_ref.authentication_method} - {failed_ref_assurance.name}) "
                        f"followed by successful fallback to lower-assurance method "
                        f"({current_event.authentication_method} - {current_assurance.name})."
                    )
                elif self.config.detect_any_downgrade:
                    transition_type = RULE_DOWNGRADE_GENERAL
                    reason = (
                        f"Authentication assurance decreased from {max_previous_assurance.name} "
                        f"({max_previous_event.authentication_method}) to {current_assurance.name} "
                        f"({current_event.authentication_method})."
                    )
                else:
                    continue

                return DriftResult(
                    drift_detected=True,
                    reason=reason,
                    previous_method=max_previous_event.authentication_method,
                    previous_assurance=max_previous_assurance,
                    current_method=current_event.authentication_method,
                    current_assurance=current_assurance,
                    transition_type=transition_type
                )

        # Check if repeated failures occurred at the same tier without downgrade
        if failure_count >= 2:
            return DriftResult(
                drift_detected=False,
                reason=f"Repeated authentication failures ({failure_count}) observed without assurance downgrade.",
                transition_type=RULE_REPEATED_FAILURES_SAME_METHOD
            )

        # Check if step-up authentication occurred
        if step_up_observed and self.config.track_step_ups:
            return DriftResult(
                drift_detected=False,
                reason="Legitimate step-up authentication observed without assurance degradation.",
                transition_type=RULE_STEP_UP_AUTHENTICATION
            )

        return DriftResult(
            drift_detected=False,
            reason="No assurance decrease detected in journey.",
            transition_type="NORMAL_JOURNEY"
        )
