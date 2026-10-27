"""
AuthDrift: Drift Detection Rules and Configuration.
Defines transparent, rule-based heuristics for detecting authentication assurance drift.
"""

from dataclasses import dataclass
from typing import Optional
from backend.models.assurance import AssuranceLevel

# Standard Rule Identifiers
RULE_DOWNGRADE_GENERAL = "RULE_DOWNGRADE_GENERAL"
RULE_FAILED_STRONG_SUCCESS_WEAK = "RULE_FAILED_STRONG_SUCCESS_WEAK"
RULE_MULTI_FAILURE_FALLBACK = "RULE_MULTI_FAILURE_FALLBACK"
RULE_REPEATED_FAILURES_SAME_METHOD = "RULE_REPEATED_FAILURES_SAME_METHOD"
RULE_STEP_UP_AUTHENTICATION = "RULE_STEP_UP_AUTHENTICATION"


@dataclass
class DriftDetectionConfig:
    """
    Configuration parameters for the drift detection engine.
    """
    # Detect any drop in assurance within a journey
    detect_any_downgrade: bool = True

    # Minimum drop in assurance tier required to flag drift (default: 1 tier)
    min_assurance_drop: int = 1

    # Require prior failure of stronger method before flagging downgrade
    require_prior_failure: bool = False

    # Track step-up authentication events (informational)
    track_step_ups: bool = True
