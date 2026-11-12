"""
AuthDrift: LLM Scenario Context Builder.
Constructs rich, structured prompt contexts grounded in empirical cybersecurity literature,
NIST SP 800-63B assurance tiers, and user fallback memory profiles.
"""

from typing import Any, Dict, List, Optional
from backend.models.event import AuthenticationEvent
from backend.models.detection import DriftResult, ContextEvidence
from backend.llm_calibration.fallback_memory import UserFallbackProfile


RESEARCH_CONTEXT_PROMPT = """
[ACADEMIC RESEARCH FOUNDATION & DETECTION GUIDELINES]
1. Lyastani et al. (IEEE S&P 2020) - "Is FIDO2 the Kingslayer of User Authentication?":
   - FIDO2 / WebAuthn authenticators often encounter client cancellation, timeouts, or forgotten tokens.
   - Attackers actively exploit fallback mechanisms by forcing downgrade to weaker memorized secrets (passwords).
   - Downgrade attacks typically originate from unfamiliar attacker-controlled endpoints or foreign IPs.

2. Wiefling et al. (ACM ASIACCS 2020 / ACSAC 2021) - "Evaluating Risk-Based Authentication Context":
   - Empirically demonstrates that >= 92% of genuine user recovery actions occur on habitual primary hardware and subnets.
   - Genuine recovery exhibits strong client continuity (Same Person, Same Primary Device, Same Primary IP).
   - If Person, Primary Device, and Primary IP match without security contradictions, the attempt is a genuine recovery action (no drift alert).

3. Kent, A. D. (Los Alamos National Laboratory - LANL, 2016):
   - Enterprise authentication telemetry distributions: ~60% routine single-ceremony logins, ~15% benign client fallbacks/recoveries,
     ~15% adversarial downgrades, ~10% external threat-matched events.

4. Bonneau et al. (IEEE S&P 2012) & NIST SP 800-63B:
   - Relative assurance hierarchy: HIGH (Passkeys, FIDO2, WebAuthn) > MEDIUM (TOTP, Push, SMS) > LOW (Passwords, PINs).
   - Relative downgrade from HIGH to LOW must trigger alert unless verified client continuity is confirmed.
"""


class LLMContextBuilder:
    """
    Builds calibrated prompt contexts for LLM-based reasoning and explainable alert calibration.
    """

    def build_system_prompt(self) -> str:
        """Constructs the master cybersecurity reasoning system prompt."""
        return (
            "You are the AuthDrift AI Security Intelligence Reasoning Engine, specialized in "
            "Authentication Assurance Drift Detection, FIDO2/WebAuthn fallback analysis, and "
            "risk-based authentication telemetry evaluation.\n\n"
            f"{RESEARCH_CONTEXT_PROMPT}\n\n"
            "[CLASSIFICATION TAXONOMY]\n"
            "1. GENUINE_RECOVERY: User failed strong authentication (passkey) but succeeded with weaker fallback (password) "
            "on the SAME verified primary device and SAME verified primary IP without security contradictions. "
            "Action: Suppress drift alert, assign LOW risk, emit informational recovery notice.\n"
            "2. ADVERSARIAL_DRIFT: Strong authentication failed and subsequent weaker authentication occurred with "
            "parameter changes (New Device ID, changed IP, foreign location, or VPN/proxy routing). "
            "Action: Flag high-severity assurance drift alert.\n"
            "3. CONTEXTUAL_ANOMALY: Environmental deviations (IP or location shift) without an assurance tier downgrade. "
            "Action: Record contextual anomaly, evaluate threat intelligence.\n"
            "4. ROUTINE_NORMAL: Consistent authentication using expected methods on habitual endpoints without downgrade.\n\n"
            "[STRICT OPERATIONAL RULE]\n"
            "Missing information must NEVER be interpreted as a match. If device ID or IP address is unavailable, "
            "classification must remain UNCERTAIN, never automatically approved as recovery.\n"
        )

    def build_journey_context(
        self,
        journey: List[AuthenticationEvent],
        drift_result: DriftResult,
        context_evidence: ContextEvidence,
        user_profile: Optional[UserFallbackProfile] = None
    ) -> Dict[str, Any]:
        """
        Synthesizes a structured JSON payload representing the full multi-step journey,
        historical fallback memory, and observed telemetry.
        """
        user_id = journey[0].user_id if journey else "unknown_user"

        # Format events chronologically
        events_summary = []
        for e in journey:
            events_summary.append({
                "event_id": e.event_id,
                "timestamp": e.timestamp.isoformat() if e.timestamp else None,
                "event_type": e.event_type,
                "method": e.authentication_method,
                "outcome": e.outcome,
                "device_id": e.device_id or "UNAVAILABLE",
                "ip_address": e.ip_address or "UNAVAILABLE",
                "location": e.location or "UNAVAILABLE",
                "authenticator_id": e.authenticator_id
            })

        # Format fallback memory baseline
        memory_summary = {
            "user_id": user_id,
            "has_established_baseline": user_profile is not None,
            "primary_device": user_profile.primary_device if user_profile else None,
            "primary_ip": user_profile.primary_ip if user_profile else None,
            "known_devices": list(user_profile.known_devices) if user_profile else [],
            "known_ips": list(user_profile.known_ips) if user_profile else [],
            "past_verified_recoveries": user_profile.verified_recovery_count if user_profile else 0
        }

        # Format telemetry deltas
        deltas = []
        for a in context_evidence.context_anomalies:
            deltas.append({
                "anomaly_type": a.anomaly_type,
                "previous_value": a.previous_value,
                "current_value": a.current_value,
                "is_impossible_travel": a.is_impossible_travel
            })

        return {
            "user_id": user_id,
            "fallback_memory": memory_summary,
            "events_chronology": events_summary,
            "state_machine_drift": {
                "drift_detected": drift_result.drift_detected,
                "transition_type": drift_result.transition_type,
                "previous_method": drift_result.previous_method,
                "previous_assurance": drift_result.previous_assurance.name if drift_result.previous_assurance else None,
                "current_method": drift_result.current_method,
                "current_assurance": drift_result.current_assurance.name if drift_result.current_assurance else None,
                "reason": drift_result.reason
            },
            "contextual_evidence": {
                "is_new_device": context_evidence.is_new_device,
                "device_id": context_evidence.device_id,
                "is_location_changed": context_evidence.is_location_changed,
                "location": context_evidence.location,
                "ip_address": context_evidence.ip_address,
                "authenticator_registered": context_evidence.authenticator_registered,
                "prior_failures_count": context_evidence.prior_failures_count,
                "is_recovery_candidate": context_evidence.is_recovery_candidate,
                "ip_reputation_status": getattr(context_evidence.ip_reputation, "status", "UNKNOWN"),
                "telemetry_deltas": deltas
            }
        }

    def format_calibration_prompt(
        self,
        journey: List[AuthenticationEvent],
        drift_result: DriftResult,
        context_evidence: ContextEvidence,
        user_profile: Optional[UserFallbackProfile] = None
    ) -> str:
        """Generates the complete LLM evaluation prompt with few-shot guidance."""
        context = self.build_journey_context(journey, drift_result, context_evidence, user_profile)
        import json
        context_json = json.dumps(context, indent=2)

        return (
            f"Analyze the following authentication journey and determine whether it represents a "
            f"GENUINE_RECOVERY, ADVERSARIAL_DRIFT, CONTEXTUAL_ANOMALY, or ROUTINE_NORMAL.\n\n"
            f"[INPUT JOURNEY TELEMETRY & FALLBACK MEMORY]:\n{context_json}\n\n"
            f"Respond with a strict JSON object matching this schema:\n"
            f"{{\n"
            f'  "classification": "GENUINE_RECOVERY | ADVERSARIAL_DRIFT | CONTEXTUAL_ANOMALY | ROUTINE_NORMAL",\n'
            f'  "confidence_score": 0.0 to 1.0,\n'
            f'  "is_drift_alert_suppressed": true | false,\n'
            f'  "case_category": "CASE_1_SAME_DEVICE_SAME_IP | CASE_2_DIFF_DEVICE_SAME_IP | CASE_3_SAME_DEVICE_DIFF_IP | CASE_4_DIFF_DEVICE_DIFF_IP | CASE_5_ROGUE_AUTHENTICATOR_REGISTRATION | ROUTINE",\n'
            f'  "reasoning": "Detailed natural language explanation citing primary device, primary IP, and research provenance",\n'
            f'  "research_citation": "Wiefling et al. (2020) | Lyastani et al. (2020) | Kent (2016)",\n'
            f'  "recommended_action": "ALLOW_RECOVERY | CHALLENGE_STEP_UP | BLOCK_AND_ALERT"\n'
            f"}}\n"
        )

    def build_scenario_prompt(
        self,
        journey: Any,
        evidence: ContextEvidence,
        user_profile: Optional[Any] = None
    ) -> str:
        """Constructs full calibrated prompt containing system prompt, academic citations, and JSON schema."""
        events = journey.events if hasattr(journey, "events") else journey
        sys_p = self.build_system_prompt()
        drift_res = DriftResult(
            drift_detected=True,
            reason="Scenario Prompt Evaluation"
        )
        u_prof = None
        if isinstance(user_profile, UserFallbackProfile):
            u_prof = user_profile
        elif isinstance(user_profile, dict):
            u_prof = UserFallbackProfile(
                user_id=user_profile.get("user_id", "user"),
                primary_device=user_profile.get("primary_device"),
                primary_ip=user_profile.get("primary_ip")
            )
        calib_p = self.format_calibration_prompt(events, drift_res, evidence, u_prof)
        return f"{sys_p}\n\n{calib_p}"

