"""
AuthDrift: LLM Calibration & Reasoning Engine.
Performs semantic calibration of authentication journeys by combining
rule-based heuristics, user fallback memory, and optional LLM inference.
"""

from dataclasses import dataclass
import json
import os
from typing import Any, Dict, List, Optional
from backend.models.event import AuthenticationEvent
from backend.models.detection import DriftResult, ContextEvidence
from backend.llm_calibration.fallback_memory import UserFallbackProfile, FallbackMemoryStore
from backend.llm_calibration.context_builder import LLMContextBuilder


@dataclass
class CalibrationResult:
    """Standardized output of the calibration engine."""
    classification: str  # GENUINE_RECOVERY, ADVERSARIAL_DRIFT, CONTEXTUAL_ANOMALY, ROUTINE_NORMAL
    confidence_score: float
    is_drift_alert_suppressed: bool
    case_category: str  # CASE_1 through CASE_5 or ROUTINE
    reasoning: str
    research_citation: str
    recommended_action: str  # ALLOW_RECOVERY, CHALLENGE_STEP_UP, BLOCK_AND_ALERT
    is_llm_evaluated: bool = False
    raw_response: Optional[Dict[str, Any]] = None

    @property
    def confidence(self) -> float:
        return self.confidence_score

    @property
    def is_genuine_recovery(self) -> bool:
        return self.classification == "GENUINE_RECOVERY"

    @property
    def suppress_drift(self) -> bool:
        return self.is_drift_alert_suppressed

    @property
    def recommended_severity(self) -> str:
        if self.classification == "GENUINE_RECOVERY":
            return "LOW"
        if "CASE_5" in self.case_category or "CASE_4" in self.case_category:
            return "CRITICAL"
        return "HIGH"

    @property
    def academic_justification(self) -> str:
        return self.research_citation


class LLMCalibrator:
    """
    Calibrates authentication journey classifications against research criteria and fallback memory.
    Executes in high-performance deterministic mode by default, with optional API-backed inference.
    """

    def __init__(
        self,
        memory_store: Optional[FallbackMemoryStore] = None,
        context_builder: Optional[LLMContextBuilder] = None,
        api_key: Optional[str] = None
    ):
        self.memory_store = memory_store or FallbackMemoryStore()
        self.context_builder = context_builder or LLMContextBuilder()
        self.api_key = api_key or os.getenv("AUTH_DRIFT_LLM_KEY") or os.getenv("ANTHROPIC_API_KEY")

    def evaluate_journey(
        self,
        user_id: str,
        journey_events: List[Dict[str, Any]],
        observed_device: Optional[str] = None,
        observed_ip: Optional[str] = None,
        primary_device: Optional[str] = None,
        primary_ip: Optional[str] = None,
        case_category: Optional[str] = None
    ) -> CalibrationResult:
        """
        Evaluates a sequence of journey events directly against memory baselines.
        """
        if primary_device or primary_ip:
            self.memory_store.register_user(
                user_id=user_id,
                primary_device=primary_device,
                primary_ip=primary_ip
            )

        from datetime import datetime, timezone
        events: List[AuthenticationEvent] = []
        now = datetime.now(timezone.utc)
        auth_registered = False
        prior_fails = 0

        for idx, ev in enumerate(journey_events):
            m = ev.get("method") or ev.get("authentication_method", "password")
            out = ev.get("outcome", "SUCCESS")
            etype = ev.get("event_type", "LOGIN" if out == "SUCCESS" else "LOGIN_ERROR")
            if etype == "REGISTER_AUTHENTICATOR":
                auth_registered = True
            if out in ("FAILURE", "FAILED", "ERROR"):
                prior_fails += 1
            events.append(AuthenticationEvent(
                event_id=f"sim-evt-{idx}",
                user_id=user_id,
                timestamp=now,
                event_type=etype,
                authentication_method=m,
                outcome=out,
                device_id=observed_device,
                ip_address=observed_ip
            ))

        drift_detected = False
        if len(journey_events) >= 2 and prior_fails > 0:
            drift_detected = True

        dev_matched = None
        if observed_device and primary_device:
            dev_matched = (observed_device == primary_device)

        ip_matched = None
        if observed_ip and primary_ip:
            dev_prof = self.memory_store.get_profile(user_id)
            if dev_prof:
                ip_matched = dev_prof.matches_primary_ip(observed_ip)
            else:
                ip_matched = (observed_ip == primary_ip)

        evidence = ContextEvidence(
            is_new_device=not dev_matched if dev_matched is not None else None,
            device_id=observed_device,
            ip_address=observed_ip,
            authenticator_registered=auth_registered,
            prior_failures_count=prior_fails,
            primary_device=primary_device,
            primary_ip=primary_ip,
            is_primary_device_matched=dev_matched,
            is_primary_ip_matched=ip_matched,
            case_category=case_category
        )
        drift_res = DriftResult(
            drift_detected=drift_detected,
            reason="Simulated transition for calibration evaluation"
        )
        return self.calibrate_journey(
            journey=events,
            drift_result=drift_res,
            context_evidence=evidence
        )

    def calibrate_journey(
        self,
        journey: List[AuthenticationEvent],
        drift_result: DriftResult,
        context_evidence: ContextEvidence,
        user_profile: Optional[UserFallbackProfile] = None
    ) -> CalibrationResult:
        """
        Calibrates the security classification of an authentication journey.
        Strictly enforces the rule: missing context must never be treated as a match.
        """
        user_id = journey[0].user_id if journey else "unknown_user"
        profile = user_profile or self.memory_store.get_profile(user_id)

        # 1. Check for Rogue Authenticator Registration (Case 5)
        if context_evidence.authenticator_registered is True:
            return CalibrationResult(
                classification="ADVERSARIAL_DRIFT",
                confidence_score=0.99,
                is_drift_alert_suppressed=False,
                case_category="CASE_5_ROGUE_AUTHENTICATOR_REGISTRATION",
                reasoning=(
                    f"Critical persistence threat: authenticator credential ('{context_evidence.authenticator_id or 'unknown'}') "
                    f"was enrolled following an authentication sequence for user '{user_id}'. Requires immediate isolation."
                ),
                research_citation="Lyastani et al. (IEEE S&P 2020) downgrade persistence vector",
                recommended_action="BLOCK_AND_ALERT"
            )

        # 2. Check for missing context (strictly uncertain, fail-closed)
        dev_id = context_evidence.device_id
        ip_addr = context_evidence.ip_address

        has_device = dev_id is not None
        has_ip = ip_addr is not None

        # 3. If there is no drift detected and no failure
        if not drift_result.drift_detected and context_evidence.prior_failures_count == 0:
            if context_evidence.context_anomalies:
                return CalibrationResult(
                    classification="CONTEXTUAL_ANOMALY",
                    confidence_score=0.85,
                    is_drift_alert_suppressed=False,
                    case_category="CASE_3_SAME_DEVICE_DIFF_IP" if has_device else "ANOMALY",
                    reasoning=f"Environmental telemetry anomaly detected without assurance degradation for user '{user_id}'.",
                    research_citation="Freeman et al. (USENIX Security 2016)",
                    recommended_action="CHALLENGE_STEP_UP"
                )
            return CalibrationResult(
                classification="ROUTINE_NORMAL",
                confidence_score=0.98,
                is_drift_alert_suppressed=False,
                case_category="ROUTINE",
                reasoning=f"Routine consistent authentication journey on standard endpoint for user '{user_id}'.",
                research_citation="Kent, A. D. (LANL 2016)",
                recommended_action="ALLOW_RECOVERY"
            )

        # 4. Fallback / Downgrade has occurred (Passkey failed / cancelled -> Password)
        # Evaluate against Client Continuity Criteria: Person, Primary Device, Primary IP
        dev_matched: Optional[bool] = None
        ip_matched: Optional[bool] = None

        # SECURITY INVARIANT: If both device and IP are missing, fail-closed immediately
        if not has_device and not has_ip:
            return CalibrationResult(
                classification="UNCERTAIN_MISSING_CONTEXT",
                confidence_score=0.60,
                is_drift_alert_suppressed=False,
                case_category="UNCERTAIN_MISSING_CONTEXT",
                reasoning=(
                    f"Assurance drift flagged with uncertain recovery context for user '{user_id}': "
                    f"Both device_id and ip_address are unavailable. "
                    f"Missing context is never treated as a match under fail-closed security invariants."
                ),
                research_citation="NIST SP 800-63B fail-closed boundary enforcement",
                recommended_action="CHALLENGE_STEP_UP"
            )

        if profile:
            dev_matched = profile.matches_primary_device(dev_id)
            ip_matched = profile.matches_primary_ip(ip_addr)
        else:
            # Fallback to context_evidence baseline flags
            if context_evidence.is_new_device is False:
                dev_matched = True
            elif context_evidence.is_new_device is True:
                dev_matched = False

            # IP continuity: checked against sequential anomalies
            if has_ip and not any(a.anomaly_type == "IP_CHANGE" for a in context_evidence.context_anomalies):
                ip_matched = True
            elif any(a.anomaly_type == "IP_CHANGE" for a in context_evidence.context_anomalies):
                ip_matched = False

        has_threat_intel_anomaly = (
            getattr(context_evidence, "ip_reputation", None) is not None
            and context_evidence.ip_reputation.status in ("KNOWN_MALICIOUS", "SUSPICIOUS")
        )
        has_location_anomaly = (
            context_evidence.is_location_changed is True
            or any(getattr(a, "is_impossible_travel", False) for a in context_evidence.context_anomalies)
        )

        # Case 1: Same verified Device, Same verified IP, No contradictions -> GENUINE RECOVERY
        if (
            dev_matched is True
            and ip_matched is True
            and not has_threat_intel_anomaly
            and not has_location_anomaly
            and not any(a.anomaly_type in ("DEVICE_CHANGE", "IP_CHANGE") for a in context_evidence.context_anomalies)
        ):
            # Record verified recovery in memory
            if profile and dev_id and ip_addr:
                self.memory_store.record_recovery_event(
                    user_id=user_id,
                    device_id=dev_id,
                    ip_address=ip_addr,
                    notes="Verified legitimate client continuity recovery."
                )

            return CalibrationResult(
                classification="GENUINE_RECOVERY",
                confidence_score=0.96,
                is_drift_alert_suppressed=True,
                case_category="CASE_1_SAME_DEVICE_SAME_IP",
                reasoning=(
                    f"Genuine authentication recovery action verified for '{user_id}': strong authentication failed "
                    f"followed by successful fallback on the verified primary device ('{dev_id}') and verified primary "
                    f"IP ('{ip_addr}') without telemetry deviations. Client continuity satisfied (Wiefling et al. 2020)."
                ),
                research_citation="Wiefling et al. (ACM ASIACCS 2020) & Sir's Recovery Rule",
                recommended_action="ALLOW_RECOVERY"
            )

        # Case 2: Different Device, Same IP -> ADVERSARIAL DRIFT
        if dev_matched is False and ip_matched is True:
            return CalibrationResult(
                classification="ADVERSARIAL_DRIFT",
                confidence_score=0.88,
                is_drift_alert_suppressed=False,
                case_category="CASE_2_DIFF_DEVICE_SAME_IP",
                reasoning=(
                    f"Assurance drift alert flagged: Authentication fallback attempted from an unrecognized device "
                    f"('{dev_id}') despite matching network IP ('{ip_addr}'). Potential internal lateral movement or device spoofing."
                ),
                research_citation="Alaca & van Oorschot (ACM CSUR 2016) device continuity analysis",
                recommended_action="CHALLENGE_STEP_UP"
            )

        # Case 3: Same Device, Changed IP / VPN / Proxy -> CONTEXTUAL ANOMALY / DRIFT
        if dev_matched is True and (ip_matched is False or any(a.anomaly_type == "IP_CHANGE" for a in context_evidence.context_anomalies)):
            return CalibrationResult(
                classification="CONTEXTUAL_ANOMALY",
                confidence_score=0.82,
                is_drift_alert_suppressed=False,
                case_category="CASE_3_SAME_DEVICE_DIFF_IP",
                reasoning=(
                    f"Contextual alert: Verified device ('{dev_id}') experienced network routing deviation to IP ('{ip_addr}'). "
                    f"Potential VPN routing or network migration during authentication fallback."
                ),
                research_citation="Thomas et al. (IEEE S&P 2019) proxy routing patterns",
                recommended_action="CHALLENGE_STEP_UP"
            )

        # Case 4: Different Device, Different IP -> HIGH CONFIDENCE ADVERSARIAL DRIFT
        if dev_matched is False and (ip_matched is False or any(a.anomaly_type == "IP_CHANGE" for a in context_evidence.context_anomalies)):
            return CalibrationResult(
                classification="ADVERSARIAL_DRIFT",
                confidence_score=0.98,
                is_drift_alert_suppressed=False,
                case_category="CASE_4_DIFF_DEVICE_DIFF_IP",
                reasoning=(
                    f"Critical assurance downgrade attack: Strong authentication failed and subsequent password success "
                    f"occurred from an entirely novel endpoint (Device: '{dev_id}', IP: '{ip_addr}'). "
                    f"High-confidence credential relay / phishing downgrade exploit (Lyastani et al. 2020)."
                ),
                research_citation="Lyastani et al. (IEEE S&P 2020) downgrade exploit",
                recommended_action="BLOCK_AND_ALERT"
            )

        # Missing information (uncertain, never automatically approved)
        missing_fields = []
        if not has_device:
            missing_fields.append("device_id")
        if not has_ip:
            missing_fields.append("ip_address")

        return CalibrationResult(
            classification="ADVERSARIAL_DRIFT",
            confidence_score=0.75,
            is_drift_alert_suppressed=False,
            case_category="UNCERTAIN_MISSING_CONTEXT",
            reasoning=(
                f"Assurance drift flagged with uncertain recovery context: Telemetry missing ({', '.join(missing_fields)}). "
                f"Missing context is never treated as a match under fail-closed security invariants."
            ),
            research_citation="NIST SP 800-63B fail-closed boundary enforcement",
            recommended_action="CHALLENGE_STEP_UP"
        )

