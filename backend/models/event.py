from dataclasses import dataclass
from typing import Optional
from datetime import datetime

@dataclass
class AuthenticationEvent:
    """
    Common normalized event schema for AuthDrift.
    
    This is the frozen shared interface between the Keycloak extraction layer
    and the assurance/detection engines.
    
    If a field is unavailable from a particular source, it should be 
    represented consistently as None rather than silently invented.
    """
    event_id: str
    user_id: str
    timestamp: datetime
    event_type: str
    authentication_method: str
    outcome: str
    
    # Contextual information (nullable if unavailable in the raw event)
    device_id: Optional[str] = None
    location: Optional[str] = None
    authenticator_id: Optional[str] = None
