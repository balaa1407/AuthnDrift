from backend.models.assurance import AssuranceLevel

def assign_assurance(method: str) -> AssuranceLevel:
    """
    Maps an authentication method to its relative assurance level.
    This fulfills Objective 2 (Assurance Assignment) for the first prototype.
    """
    if not method:
        return AssuranceLevel.LOW
        
    normalized_method = method.strip().lower()
    
    if normalized_method == 'passkey':
        return AssuranceLevel.HIGH
    elif normalized_method == 'otp':
        return AssuranceLevel.MEDIUM
    elif normalized_method == 'password':
        return AssuranceLevel.LOW
    
    # Default fallback for unknown methods
    return AssuranceLevel.LOW
