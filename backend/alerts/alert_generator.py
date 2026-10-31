"""
AuthDrift: Explainable Alert Generator.
Produces human-readable and machine-readable explainable security alerts
derived strictly from empirical journey evidence and formal state-machine logic.
Distinguishes ASSURANCE_DRIFT from CONTEXTUAL_ANOMALY.
"""

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from backend.models.event import AuthenticationEvent
from backend.models.detection import (
    DriftResult,
    ContextEvidence,
    RiskAssessment,
    SecurityAlert,
    AlertPriority
)


class AlertGenerator:
    """
    Generates explainable, verifiable security alerts.
    Never invents contextual details; strictly adheres to evidence present.
    Explicitly links qualifying source and target events and records discrete
    context anomalies and failed authentications.
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
        methods_involved = [e.authentication_method for e in journey if e.authentication_method]

        # Preserve chronological ordering when reporting distinct methods
        unique_methods_ordered = list(dict.fromkeys(methods_involved))

        # Collect discrete failed authentications
        failed_authentications: List[Dict[str, Any]] = [
            {
                "event_id": e.event_id,
                "event_type": e.event_type,
                "authentication_method": e.authentication_method,
                "timestamp": e.timestamp.isoformat() if e.timestamp else None,
                "location": e.location,
                "ip_address": e.ip_address,
                "device_id": e.device_id,
                "lifecycle_stage": getattr(e, "event_category", "AUTHENTICATION"),
            }
            for e in journey
            if e.outcome and str(e.outcome).strip().upper() in ["FAILURE", "FAILED", "ERROR"]
        ]

        # Classify alert type
        has_context_anomaly = (
            bool(context_evidence.context_anomalies)
            or context_evidence.is_new_device is True
            or context_evidence.is_location_changed is True
            or context_evidence.authenticator_registered is True
            or context_evidence.prior_failures_count >= 2
            or risk_assessment.score > 0
        )

        if drift_result.drift_detected:
            alert_type = "ASSURANCE_DRIFT"
        elif has_context_anomaly:
            alert_type = "CONTEXTUAL_ANOMALY"
        else:
            alert_type = "INFORMATIONAL"

        # Determine source and target event references
        if drift_result.drift_detected:
            source_event_id = drift_result.source_event_id
            target_event_id = drift_result.target_event_id
        elif context_evidence.context_anomalies:
            source_event_id = context_evidence.context_anomalies[0].source_event_id
            target_event_id = context_evidence.context_anomalies[0].target_event_id
        else:
            source_event_id = None
            target_event_id = None

        # Generate narrative explanation
        explanation_parts: List[str] = []

        if alert_type == "ASSURANCE_DRIFT":
            methods_str = ", ".join(unique_methods_ordered) if unique_methods_ordered else "unspecified"
            explanation_parts.append(
                f"Authentication assurance drift detected for user '{user_id}'. "
                f"Journey contained {len(journey)} events involving methods: {methods_str}."
            )
            explanation_parts.append(f"Transition Analysis: {drift_result.reason}")
        elif alert_type == "CONTEXTUAL_ANOMALY":
            explanation_parts.append(
                f"Contextual anomaly detected for user '{user_id}' without authentication assurance drift. "
                f"Journey contained {len(journey)} events."
            )
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
            p_loc = f" (primary baseline: '{context_evidence.primary_location}')" if context_evidence.primary_location else ""
            context_notes.append(f"new location observed ('{context_evidence.location}'){p_loc}")
        elif context_evidence.location_status == "KNOWN" and context_evidence.location:
            context_notes.append(f"location confirmed matching baseline ('{context_evidence.location}')")

        if context_evidence.authenticator_registered is True:
            reg_id = f" ('{context_evidence.authenticator_id}')" if context_evidence.authenticator_id else ""
            context_notes.append(f"an authenticator credential was registered following authentication{reg_id}")

        if context_evidence.ip_address:
            context_notes.append(f"observed IP address: {context_evidence.ip_address}")

        if context_evidence.context_anomalies:
            anomaly_descriptions = [f"{a.anomaly_type} ({a.previous_value or 'None'} -> {a.current_value})" for a in context_evidence.context_anomalies]
            context_notes.append(f"telemetry deltas: {', '.join(anomaly_descriptions)}")

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
        elif alert_type == "CONTEXTUAL_ANOMALY":
            explanation_parts.append(
                "Notice: Contextual deviations alone (e.g. traveling or new client) do not constitute proof of compromise."
            )

        is_actionable = drift_result.drift_detected or (risk_assessment.score >= 50)

        # Determine Operational Priority Tier
        if risk_assessment.score >= 60 or context_evidence.authenticator_registered is True:
            priority = AlertPriority.HIGH_PRIORITY.value
        elif drift_result.drift_detected or risk_assessment.score >= 30:
            priority = AlertPriority.INVESTIGATION_REQUIRED.value
        else:
            priority = AlertPriority.INFORMATIONAL.value

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
            session_id=session_id or (journey[0].session_id if journey else None),
            priority=priority,
            alert_type=alert_type,
            source_event_id=source_event_id,
            target_event_id=target_event_id,
            context_anomalies=context_evidence.context_anomalies,
            failed_authentications=failed_authentications
        )
