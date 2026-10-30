"""
AuthDrift: Detection and Security Alert Data Contracts.
Standardized output models for drift detection, contextual correlation,
risk assessment, and explainable security alerts.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional
from backend.models.assurance import AssuranceLevel


class RiskSeverity(str, Enum):
    """
    Configurable severity classifications for detected risk.
    """
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class DriftResult:
    """
    The standardized output contract for the drift detection engine.
    Fulfills the requirement to output an explainable result rather
    than just an 'Attack Detected' flag.
    """
    drift_detected: bool
    reason: str
    previous_method: Optional[str] = None
    previous_assurance: Optional[AssuranceLevel] = None
    current_method: Optional[str] = None
    current_assurance: Optional[AssuranceLevel] = None
    transition_type: Optional[str] = None


@dataclass
class ContextEvidence:
    """
    Contextual signals observed during journey analysis.
    Explicitly tracks whether signals were confirmed, absent, or unavailable.
    """
    is_new_device: Optional[bool] = None
    device_id: Optional[str] = None
    is_location_changed: Optional[bool] = None
    location: Optional[str] = None
    authenticator_registered: Optional[bool] = None
    authenticator_id: Optional[str] = None
    prior_failures_count: int = 0
    evidence_notes: List[str] = field(default_factory=list)


@dataclass
class RiskAssessment:
    """
    Transparent, configurable risk assessment calculation result.
    """
    score: int
    severity: RiskSeverity
    triggered_factors: List[str] = field(default_factory=list)
    factor_breakdown: Dict[str, int] = field(default_factory=dict)
    rationale: str = ""


@dataclass
class SecurityAlert:
    """
    Comprehensive explainable security alert for Rohan's dashboard and SIEM export.
    """
    alert_id: str
    user_id: str
    timestamp: datetime
    drift_detected: bool
    drift_result: DriftResult
    context_evidence: ContextEvidence
    risk_assessment: RiskAssessment
    methods_involved: List[str]
    explanation: str
    is_actionable: bool
    session_id: Optional[str] = None
