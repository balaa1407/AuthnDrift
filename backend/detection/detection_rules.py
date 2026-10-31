"""
AuthDrift: Drift Detection Rules and Configuration.
Defines transparent, rule-based heuristics for detecting authentication assurance drift.
"""

from dataclasses import dataclass
from typing import Optional
from backend.models.assurance import AssuranceLevel

# Standard Rule Identifiers
RULE_CROSS_CEREMONY_DOWNGRADE = "RULE_CROSS_CEREMONY_DOWNGRADE"
RULE_DOWNGRADE_GENERAL = RULE_CROSS_CEREMONY_DOWNGRADE  # Backward-compatible alias for Rule B
RULE_FAILED_STRONG_SUCCESS_WEAK = "RULE_FAILED_STRONG_SUCCESS_WEAK"
RULE_MULTI_FAILURE_FALLBACK = "RULE_MULTI_FAILURE_FALLBACK"
RULE_REPEATED_FAILURES_SAME_METHOD = "RULE_REPEATED_FAILURES_SAME_METHOD"
RULE_STEP_UP_AUTHENTICATION = "RULE_STEP_UP_AUTHENTICATION"


@dataclass
class DriftDetectionConfig:
    """
    Configuration parameters for the drift detection engine.

    Rule Architecture:
      - Rule A (Active Fallback Downgrade / Intra-Attempt Bypass):
        Detects when a stronger authentication method fails and is immediately
        followed by a successful lower-assurance fallback ceremony in the same journey.
        Always active when `detect_any_downgrade=True`.
        Transition type: RULE_FAILED_STRONG_SUCCESS_WEAK or RULE_MULTI_FAILURE_FALLBACK.

      - Rule B (Cross-Ceremony Step-Down / Baseline Policy Drift):
        Detects when two consecutive successful AUTHENTICATION events show decreasing
        effective assurance without an intervening failed ceremony.
        Active when `detect_any_downgrade=True` and `require_prior_failure=False`.
        Transition type: RULE_CROSS_CEREMONY_DOWNGRADE.

    Security Policy Trade-off:
      Rule B is ENABLED BY DEFAULT (`require_prior_failure=False`).
      Implication: In environments where users legitimately switch between different
      assurance mechanisms (e.g., logging in with Passkey at the office and later logging
      in with Password from a mobile client), Rule B will flag these cross-ceremony step-downs.
      To suppress cross-ceremony step-down alerts and restrict detection strictly to active
      fallback attacks (failed strong -> successful weak), configure `require_prior_failure=True`.
    """
    # Detect any drop in assurance within a journey (master toggle for Rule A and Rule B)
    detect_any_downgrade: bool = True

    # Minimum drop in assurance tier required to flag drift (default: 1 tier)
    min_assurance_drop: int = 1

    # Require prior failure of stronger method before flagging downgrade.
    # Default is False: Rule B (cross-ceremony downgrade without prior failure) is ENABLED.
    # Set to True to disable Rule B and require prior failure (Rule A only).
    require_prior_failure: bool = False

    # Track step-up authentication events (informational, never flagged as drift)
    track_step_ups: bool = True
