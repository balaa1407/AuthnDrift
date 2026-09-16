from typing import List
from backend.models.event import AuthenticationEvent
from backend.models.detection import DriftResult
from backend.assurance.assigner import assign_assurance

def detect_drift(journey: List[AuthenticationEvent]) -> DriftResult:
    """
    Analyzes a reconstructed authentication journey to detect assurance drift.
    
    Rule: IF a stronger authentication method is followed by a weaker 
    authentication method WITHIN THE SAME AUTHENTICATION JOURNEY 
    THEN flag an authentication assurance decrease/drift.
    """
    if not journey or len(journey) < 2:
        return DriftResult(
            drift_detected=False, 
            reason="Insufficient events to detect drift."
        )
        
    # We track the highest assurance seen so far to compare against subsequent methods
    max_assurance_event = journey[0]
    max_assurance_val = assign_assurance(max_assurance_event.authentication_method)
    
    for current_event in journey[1:]:
        current_assurance_val = assign_assurance(current_event.authentication_method)
        
        # If we see a decrease in assurance compared to the highest previous method
        if current_assurance_val.value < max_assurance_val.value:
            return DriftResult(
                drift_detected=True,
                reason=f"Authentication assurance decreased from {max_assurance_val.name} ({max_assurance_event.authentication_method}) to {current_assurance_val.name} ({current_event.authentication_method}).",
                previous_method=max_assurance_event.authentication_method,
                previous_assurance=max_assurance_val,
                current_method=current_event.authentication_method,
                current_assurance=current_assurance_val
            )
            
        # Update max assurance seen if current is higher (e.g. stepping up authentication)
        if current_assurance_val.value > max_assurance_val.value:
            max_assurance_event = current_event
            max_assurance_val = current_assurance_val
            
    return DriftResult(
        drift_detected=False, 
        reason="No assurance decrease detected in journey."
    )
