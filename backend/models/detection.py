from dataclasses import dataclass
from typing import Optional
from backend.models.assurance import AssuranceLevel

@dataclass
class DriftResult:
    """
    The standardized output contract for the drift detection engine.
    
    This fulfills the requirement to output an explainable result rather 
    than just an 'Attack Detected' flag.
    """
    drift_detected: bool
    reason: str
    previous_method: Optional[str] = None
    previous_assurance: Optional[AssuranceLevel] = None
    current_method: Optional[str] = None
    current_assurance: Optional[AssuranceLevel] = None
