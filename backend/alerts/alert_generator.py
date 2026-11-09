"""
AuthDrift: Explainable Alert Generator.
Produces human-readable and machine-readable explainable security alerts
derived strictly from empirical journey evidence, formal state-machine logic,
and IP threat intelligence reputation telemetry.
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
from backend.assurance.assurance_model import AssuranceModel


class AlertGenerator:
    """
    Generates explainable, verifiable security alerts.
    Never invents contextual details; strictly adheres to evidence present.
    Explicitly links qualifying source and target events and records discrete
    context anomalies, failed authentications, and IP threat intelligence.
    """

    def __init__(self, assurance_model: Optional[AssuranceModel] = None):
        self.assurance_model = assurance_model or AssuranceModel()

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
        is_recovery = getattr(context_evidence, "is_recovery_candidate", False)

        has_context_anomaly = (
            bool(context_evidence.context_anomalies)
            or context_evidence.is_new_device is True
            or context_evidence.is_location_changed is True
            or context_evidence.authenticator_registered is True
            or context_evidence.prior_failures_count >= 2
            or (
                getattr(context_evidence, "ip_reputation", None) is not None
                and context_evidence.ip_reputation.status in ("KNOWN_MALICIOUS", "SUSPICIOUS")
            )
            or risk_assessment.score > 0
        )

        if is_recovery:
            alert_type = "INFORMATIONAL"
            drift_detected_flag = False
        elif drift_result.drift_detected:
            alert_type = "ASSURANCE_DRIFT"
            drift_detected_flag = True
        elif has_context_anomaly:
            alert_type = "CONTEXTUAL_ANOMALY"
            drift_detected_flag = False
        else:
            alert_type = "INFORMATIONAL"
            drift_detected_flag = False

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

        if is_recovery:
            methods_str = ", ".join(unique_methods_ordered) if unique_methods_ordered else "unspecified"
            explanation_parts.append(
                f"Legitimate authentication recovery candidate identified for user '{user_id}'. "
                f"Failed strong authentication followed by successful password fallback on verified known device "
                f"('{context_evidence.device_id or 'known'}') and matching IP address. "
                f"Journey contained {len(journey)} events involving methods: {methods_str}. "
                f"No assurance drift alert generated."
            )
            explanation_parts.append(f"Transition Details: {drift_result.reason}")
        elif alert_type == "ASSURANCE_DRIFT":
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

        # Threat Intelligence signals
        if getattr(context_evidence, "ip_reputation", None) is not None:
            rep = context_evidence.ip_reputation
            if rep.status != "UNKNOWN":
                score_str = f", Abuse Score: {rep.abuse_confidence_score}%" if rep.abuse_confidence_score is not None else ""
                reports_str = f", Reports: {rep.total_reports}" if rep.total_reports is not None else ""
                context_notes.append(
                    f"threat intelligence from {rep.provider} flagged IP as {rep.status}{score_str}{reports_str}"
                )

        if context_evidence.context_anomalies:
            anomaly_descriptions = []
            for a in context_evidence.context_anomalies:
                desc = f"{a.anomaly_type} ({a.previous_value or 'None'} -> {a.current_value})"
                if getattr(a, "is_impossible_travel", False) and getattr(a, "velocity_kmh", None):
                    desc += f" [IMPOSSIBLE TRAVEL: {a.velocity_kmh:.1f} km/h]"
                anomaly_descriptions.append(desc)
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
                "Notice: Contextual deviations alone (e.g. traveling, new client, or suspicious network) do not constitute conclusive proof of account compromise."
            )

        is_actionable = False if is_recovery else (drift_detected_flag or (risk_assessment.score >= 50))

        # Cryptographic boundary transition
        cryptographic_boundary = None
        if drift_result.previous_method or drift_result.current_method:
            cryptographic_boundary = self.assurance_model.get_cryptographic_boundary_transition(
                drift_result.previous_method,
                drift_result.current_method
            )

        # Actionable Remediation Guidance
        actionable_remediation: List[str] = []
        is_malicious_ip = bool(
            getattr(context_evidence, "ip_reputation", None)
            and context_evidence.ip_reputation.status == "KNOWN_MALICIOUS"
        )

        if is_recovery:
            actionable_remediation.append("Autonomous Client Continuity Policy (ACCP): Verified self-service recovery on known hardware and subnet. Maintain standard telemetry monitoring.")
            actionable_remediation.append("Recommend proactive re-verification or re-enrollment of hardware passkey if client hardware issues persist.")
        else:
            if drift_detected_flag:
                actionable_remediation.append("Revoke active session tokens immediately and invalidate downstream OAuth2/OIDC refresh tokens.")
                actionable_remediation.append("Enforce mandatory step-up re-authentication using a phishing-resistant credential (FIDO2 / WebAuthn) on an enrolled endpoint.")
            if is_malicious_ip:
                actionable_remediation.append(f"Block origin IP address ({context_evidence.ip_address}) at perimeter WAF / security group; isolate active sessions originating from this subnet.")
            
            # Check for impossible travel
            has_impossible_travel = any(getattr(a, "is_impossible_travel", False) for a in context_evidence.context_anomalies)
            if has_impossible_travel:
                actionable_remediation.append("Geodesic velocity violation: Terminate all concurrent user sessions and require physical out-of-band identity verification.")
            
            if context_evidence.authenticator_registered is True:
                actionable_remediation.append("Quarantine newly registered authenticator credential immediately until user identity and device integrity are confirmed.")
            elif context_evidence.is_new_device is True and not is_recovery:
                actionable_remediation.append("Challenge unfamiliar endpoint via MDM / EDR health attestation prior to granting zero-trust resource access.")
            
            if not actionable_remediation:
                actionable_remediation.append("No immediate containment required. Continue standard behavioral profiling.")

        # Determine Operational Priority Tier
        if risk_assessment.score >= 60 or context_evidence.authenticator_registered is True or is_malicious_ip:
            priority = AlertPriority.HIGH_PRIORITY.value
        elif (not is_recovery and drift_detected_flag) or risk_assessment.score >= 30:
            priority = AlertPriority.INVESTIGATION_REQUIRED.value
        else:
            priority = AlertPriority.INFORMATIONAL.value

        return SecurityAlert(
            alert_id=alert_id,
            user_id=user_id,
            timestamp=timestamp,
            drift_detected=drift_detected_flag,
            drift_result=drift_result,
            context_evidence=context_evidence,
            risk_assessment=risk_assessment,
            methods_involved=methods_involved,
            explanation=" ".join(explanation_parts),
            is_actionable=is_actionable,
            session_id=session_id or (journey[0].session_id if journey else None),
            priority=priority,
            alert_type=alert_type,
            is_recovery_candidate=is_recovery,
            source_event_id=source_event_id,
            target_event_id=target_event_id,
            context_anomalies=context_evidence.context_anomalies,
            failed_authentications=failed_authentications,
            ip_reputation=getattr(context_evidence, "ip_reputation", None),
            actionable_remediation=actionable_remediation,
            cryptographic_boundary=cryptographic_boundary
        )
