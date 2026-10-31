"""
AuthDrift: Common Normalized Authentication Event and Journey Schemas.
Represents vendor-neutral normalized authentication events.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Optional
from backend.models.assurance import AssuranceLevel


class EventCategory(str, Enum):
    """
    Formal classification of event lifecycle stages derived strictly from IdP schemas.
    """
    AUTHENTICATION = "AUTHENTICATION"
    SESSION_LIFECYCLE = "SESSION_LIFECYCLE"
    ACCOUNT_LIFECYCLE = "ACCOUNT_LIFECYCLE"


@dataclass
class AuthenticationEvent:
    """
    Common normalized event schema for AuthDrift.

    This is the frozen shared interface between the Keycloak extraction layer
    and the assurance/detection engines.

    If a field is unavailable from a particular source, it is represented
    consistently as None rather than silently invented.
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
    ip_address: Optional[str] = None
    authenticator_id: Optional[str] = None
    session_id: Optional[str] = None
    source_provider: Optional[str] = "keycloak"

    # Formal state-machine attributes
    event_category: str = EventCategory.AUTHENTICATION.value
    effective_assurance: Optional[AssuranceLevel] = None
    attempted_assurance: Optional[AssuranceLevel] = None


@dataclass
class AuthenticationJourney:
    """
    Chronological grouping of authentication events for a user session or window.
    """
    user_id: str
    events: List[AuthenticationEvent] = field(default_factory=list)
    session_id: Optional[str] = None

    def add_event(self, event: AuthenticationEvent) -> None:
        if event.user_id != self.user_id:
            raise ValueError(
                f"Cannot add event with user_id '{event.user_id}' to journey of user '{self.user_id}'"
            )
        self.events.append(event)
        self.events.sort(key=lambda e: e.timestamp)
