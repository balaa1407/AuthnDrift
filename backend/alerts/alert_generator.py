"""
AuthDrift: Explainable Alert Generator.
Produces human-readable and machine-readable explainable security alerts
derived strictly from empirical journey evidence.
"""

import uuid
from datetime import datetime, timezone
from typing import List, Optional
from backend.models.event import AuthenticationEvent
from backend.models.detection import DriftResult, ContextEvidence, RiskAssessment, SecurityAlert


class AlertGenerator:
    """
    Generates explainable, verifiable security alerts.
    Never invents contextual details; strictly adheres to evidence present.
    """

    def generate_alert(
        self,
        journey: List[AuthenticationEvent],
        drift_result: DriftResult,
        context_evidence: ContextEvidence,
        risk_assessment: RiskAssessment,
        session_id: Optional[str] = None
    ) -> SecurityAlert:
        alert_id = f"alert-{uuid.uuid4().hex[:12]}"
        user_id = journey[0].user_id if journey else "unknown_user"
        timestamp = journey[-1].timestamp if journey else datetime.now(timezone.utc)
        methods_involved = [e.authentication_method for e in journey]

        # Generate narrative explanation
        explanation_parts: List[str] = []

        if drift_result.drift_detected:
            explanation_parts.append(
                f"Authentication assurance drift detected for user '{user_id}'. "
                f"Journey contained {len(journey)} events involving methods: {', '.join(set(methods_involved))}."
            )
            explanation_parts.append(f"Transition Analysis: {drift_result.reason}")
        else:
            explanation_parts.append(
                f"Authentication journey analyzed for user '{user_id}'. "
                f"No assurance degradation detected."
            )

        # Contextual Signals
        context_notes = []
        if context_evidence.is_new_device is True:
            context_notes.append(f"authentication completed from a new device ('{context_evidence.device_id}')")
        elif context_evidence.is_new_device is False:
            context_notes.append(f"authentication completed from a known device ('{context_evidence.device_id}')")

        if context_evidence.is_location_changed is True:
            context_notes.append(f"location changed to '{context_evidence.location}'")

        if context_evidence.authenticator_registered is True:
            context_notes.append("a new authenticator credential was registered following authentication")

        if context_notes:
            explanation_parts.append(f"Contextual Signals: Identified {', '.join(context_notes)}.")

        # Risk Rationale
        explanation_parts.append(f"Risk Assessment: {risk_assessment.rationale}")

        # Distinguish Legitimate Downgrade from Confirmed Attack
        if drift_result.drift_detected:
            explanation_parts.append(
                "Notice: An assurance downgrade is not definitive proof of an active compromise. "
                "Legitimate factors such as forgotten hardware authenticators, browser incompatibility, "
                "or device migration can trigger fallback. Verification is recommended based on risk severity."
            )

        is_actionable = drift_result.drift_detected or (risk_assessment.score >= 50)

        return SecurityAlert(
            alert_id=alert_id,
            user_id=user_id,
            timestamp=timestamp,
            drift_detected=drift_result.drift_detected,
            drift_result=drift_result,
            context_evidence=context_evidence,
            risk_assessment=risk_assessment,
            methods_involved=methods_involved,
            explanation=" ".join(explanation_parts),
            is_actionable=is_actionable,
            session_id=session_id or (journey[0].session_id if journey else None)
        )
