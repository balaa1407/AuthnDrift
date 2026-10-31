"""
AuthDrift: Core Drift Detection Engine.
Analyses reconstructed authentication journeys and flags assurance downgrades
with explicit chronological transition logic, pure state-machine invariants,
and supporting empirical evidence.
"""

from datetime import datetime
from typing import List, Optional, Set
from backend.models.event import AuthenticationEvent, EventCategory
from backend.models.detection import DriftResult
from backend.models.assurance import AssuranceLevel
from backend.assurance.assurance_model import AssuranceModel
from backend.assurance.assurance_assignment import assign_event_assurance
from backend.detection.detection_rules import (
    DriftDetectionConfig,
    RULE_DOWNGRADE_GENERAL,
    RULE_FAILED_STRONG_SUCCESS_WEAK,
    RULE_MULTI_FAILURE_FALLBACK,
    RULE_REPEATED_FAILURES_SAME_METHOD,
    RULE_STEP_UP_AUTHENTICATION
)

# Lifecycle events representing credential management or session control.
# These participate in contextual correlation, not assurance drift detection.
LIFECYCLE_EVENT_TYPES: Set[str] = {
    "REGISTER_AUTHENTICATOR",
    "UPDATE_CREDENTIAL",
    "DELETE_CREDENTIAL",
    "CREDENTIAL_REGISTER",
    "LOGOUT",
    "SESSION_LOGOUT",
    "USER.MFA.FACTOR.ACTIVATE",
    "FACTOR.ENROLL",
    "USER.CREDENTIAL.ENROLL",
    "REFRESH_TOKEN",
    "REFRESH_TOKEN_ERROR",
    "CODE_TO_TOKEN",
    "CODE_TO_TOKEN_ERROR",
}


def _is_failure_outcome(outcome: Optional[str]) -> bool:
    """Helper to safely evaluate failure outcomes without crashing on None or non-string."""
    if not outcome:
        return False
    return str(outcome).strip().upper() in ["FAILURE", "FAILED", "ERROR"]


class DriftDetector:
    """
    Evaluates authentication journeys for assurance drift using strict state-machine logic.

    Guarantees:
    - Events evaluated in strict chronological timestamp order.
    - Only interactive authentication ceremonies (event_category == AUTHENTICATION)
      enter the assurance-level comparison domain.
    - Session lifecycle events (e.g. REFRESH_TOKEN) and factor mutations never enter
      assurance comparison and cannot be downgrade targets.
    - Downgrades flagged only when a weaker method succeeds after a stronger method failed
      (Active Fallback Downgrade / Rule A), or when an explicit cross-ceremony downgrade occurs
      between consecutive successful authentications (Rule B).
    - Repeated failures alone are never labeled as assurance drift.
    - Step-up authentications are recognized as legitimate security enhancements, not downgrades.
    - Unknown authentication methods are conservatively assigned to LOW and made explicit.
    - The drift result explicitly cites source_event_id and target_event_id.
    """

    def __init__(
        self,
        config: Optional[DriftDetectionConfig] = None,
        assurance_model: Optional[AssuranceModel] = None
    ):
        self.config = config or DriftDetectionConfig()
        self.assurance_model = assurance_model or AssuranceModel()

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

        # 1. Defensively ensure events are chronologically ordered (handle None timestamps safely)
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

        # 3. Defensive assurance domain annotation for events
        for event in deduped_journey:
            if event.effective_assurance is None and event.attempted_assurance is None:
                assign_event_assurance(event, self.assurance_model)

        # 4. Filter for interactive authentication events only
        # Session lifecycle events (REFRESH_TOKEN) and factor mutations are excluded from assurance comparison.
        auth_events = [
            e for e in deduped_journey
            if getattr(e, "event_category", EventCategory.AUTHENTICATION.value) == EventCategory.AUTHENTICATION.value
            and str(e.event_type or "").strip().upper() not in LIFECYCLE_EVENT_TYPES
        ]

        if len(auth_events) < 2:
            return DriftResult(
                drift_detected=False,
                reason="Insufficient authentication events in journey to detect drift (minimum 2 required)."
            )

        # 5. State tracking for chronological transition evaluation
        pending_failures: List[AuthenticationEvent] = []
        last_successful_event: Optional[AuthenticationEvent] = None
        detected_drift: Optional[DriftResult] = None
        total_failures = 0
        step_up_observed = False

        for current_event in auth_events:
            current_method = current_event.authentication_method
            current_assurance, is_recognized = self.assurance_model.get_assurance_level(current_method)
            current_is_failure = _is_failure_outcome(current_event.outcome)

            if current_is_failure:
                total_failures += 1
                pending_failures.append(current_event)
                # A failure alone does NOT flag assurance drift - must await subsequent outcome
                continue

            # Current event is a SUCCESS!
            # Evaluate against pending failures (failed strong followed by weaker fallback - Rule A)
            if pending_failures:
                # Find the strongest method among pending failures
                strongest_failed_event = max(
                    pending_failures,
                    key=lambda f: self.assurance_model.get_assurance_level(f.authentication_method)[0].value
                )
                strongest_failed_assurance, failed_is_rec = self.assurance_model.get_assurance_level(
                    strongest_failed_event.authentication_method
                )

                assurance_drop = strongest_failed_assurance.value - current_assurance.value

                if assurance_drop >= self.config.min_assurance_drop:
                    # Confirmed downgrade: weaker method succeeded after stronger method failed
                    unknown_notes = []
                    if not failed_is_rec:
                        unknown_notes.append(f"'{strongest_failed_event.authentication_method}' is an unknown method evaluated defensively as LOW assurance")
                    if not is_recognized:
                        unknown_notes.append(f"'{current_method}' is an unknown method evaluated defensively as LOW assurance")
                    unknown_suffix = f" (Note: {'; '.join(unknown_notes)})." if unknown_notes else ""

                    if len(pending_failures) > 1:
                        transition_type = RULE_MULTI_FAILURE_FALLBACK
                        reason = (
                            f"Multiple failed authentication attempts ({len(pending_failures)}) including stronger method "
                            f"'{strongest_failed_event.authentication_method}' ({strongest_failed_assurance.name}) "
                            f"followed by successful fallback to lower-assurance method '{current_method}' "
                            f"({current_assurance.name}){unknown_suffix}."
                        )
                    else:
                        transition_type = RULE_FAILED_STRONG_SUCCESS_WEAK
                        reason = (
                            f"Failed strong authentication ({strongest_failed_event.authentication_method} - {strongest_failed_assurance.name}) "
                            f"followed by successful fallback to lower-assurance method "
                            f"({current_method} - {current_assurance.name}){unknown_suffix}."
                        )

                    detected_drift = DriftResult(
                        drift_detected=True,
                        reason=reason,
                        previous_method=strongest_failed_event.authentication_method,
                        previous_assurance=strongest_failed_assurance,
                        current_method=current_method,
                        current_assurance=current_assurance,
                        transition_type=transition_type,
                        source_event_id=strongest_failed_event.event_id,
                        target_event_id=current_event.event_id
                    )
                elif current_assurance.value > strongest_failed_assurance.value:
                    step_up_observed = True

                # Attempt concluded with a success; clear pending failures
                pending_failures.clear()

            else:
                # No pending failure: consecutive successful authentications (Rule B)
                if last_successful_event:
                    last_assurance, last_is_rec = self.assurance_model.get_assurance_level(
                        last_successful_event.authentication_method
                    )
                    if current_assurance.value > last_assurance.value:
                        step_up_observed = True
                    elif current_assurance.value < last_assurance.value:
                        assurance_drop = last_assurance.value - current_assurance.value
                        if assurance_drop >= self.config.min_assurance_drop and self.config.detect_any_downgrade and not self.config.require_prior_failure:
                            unknown_notes = []
                            if not last_is_rec:
                                unknown_notes.append(f"'{last_successful_event.authentication_method}' is an unknown method evaluated defensively as LOW assurance")
                            if not is_recognized:
                                unknown_notes.append(f"'{current_method}' is an unknown method evaluated defensively as LOW assurance")
                            unknown_suffix = f" (Note: {'; '.join(unknown_notes)})." if unknown_notes else ""

                            detected_drift = DriftResult(
                                drift_detected=True,
                                reason=(
                                    f"Authentication assurance decreased from {last_assurance.name} "
                                    f"({last_successful_event.authentication_method}) to {current_assurance.name} "
                                    f"({current_method}){unknown_suffix}."
                                ),
                                previous_method=last_successful_event.authentication_method,
                                previous_assurance=last_assurance,
                                current_method=current_method,
                                current_assurance=current_assurance,
                                transition_type=RULE_DOWNGRADE_GENERAL,
                                source_event_id=last_successful_event.event_id,
                                target_event_id=current_event.event_id
                            )

            last_successful_event = current_event

        # 6. Return evaluation outcome
        if detected_drift:
            return detected_drift

        # Check for repeated failures without assurance downgrade
        if total_failures >= 2:
            return DriftResult(
                drift_detected=False,
                reason=f"Repeated authentication failures ({total_failures}) observed without assurance downgrade.",
                transition_type=RULE_REPEATED_FAILURES_SAME_METHOD
            )

        # Check for step-up authentication
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
