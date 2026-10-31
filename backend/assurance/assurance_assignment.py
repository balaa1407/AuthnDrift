"""
AuthDrift: Assurance Assignment Interface.
Assigns relative assurance levels to authentication methods and normalized events
according to the formal state-machine domain restriction invariants.
"""

from typing import Optional
from backend.models.assurance import AssuranceLevel
from backend.models.event import AuthenticationEvent, EventCategory
from backend.assurance.assurance_model import AssuranceModel

_DEFAULT_MODEL = AssuranceModel()


def assign_assurance(
    method: Optional[str],
    model: Optional[AssuranceModel] = None
) -> AssuranceLevel:
    """
    Maps an authentication method to its relative assurance level.
    Defensively defaults to LOW for unknown methods.
    """
    active_model = model or _DEFAULT_MODEL
    level, _ = active_model.get_assurance_level(method)
    return level


def get_assurance_justification(
    method: Optional[str],
    model: Optional[AssuranceModel] = None
) -> str:
    """
    Retrieves the security reasoning for an assigned assurance level.
    """
    active_model = model or _DEFAULT_MODEL
    return active_model.get_rationale(method)


def is_high_assurance(
    method: Optional[str],
    model: Optional[AssuranceModel] = None
) -> bool:
    """
    Returns True if the method represents a HIGH assurance authenticator.
    """
    return assign_assurance(method, model) == AssuranceLevel.HIGH


def assign_event_assurance(
    event: AuthenticationEvent,
    model: Optional[AssuranceModel] = None
) -> AuthenticationEvent:
    """
    Assigns effective and attempted assurance according to formal state-machine invariants:
    - Effective Assurance A_eff(e): Assigned iff event.event_category == AUTHENTICATION,
      event.authentication_method is present, and event.outcome == 'SUCCESS'.
    - Attempted Assurance A_attempted(e): Assigned iff event.event_category == AUTHENTICATION,
      event.authentication_method is present, and event.outcome in ['FAILURE', 'ERROR'].
    - When event.event_category is SESSION_LIFECYCLE or ACCOUNT_LIFECYCLE, or when
      event.authentication_method is missing:
      A_eff(e) = None and A_attempted(e) = None, because non-interactive token rotations,
      factor mutations, or unclassified non-ceremony events do not execute recognized factor ceremonies.
    """
    active_model = model or _DEFAULT_MODEL
    category = getattr(event, "event_category", EventCategory.AUTHENTICATION.value)
    outcome = str(event.outcome or "").strip().upper()

    if (category == EventCategory.AUTHENTICATION.value or category == "AUTHENTICATION") and event.authentication_method:
        if outcome in ["SUCCESS", "ALLOW"]:
            event.effective_assurance, _ = active_model.get_assurance_level(event.authentication_method)
            event.attempted_assurance = None
        else:
            event.effective_assurance = None
            event.attempted_assurance, _ = active_model.get_assurance_level(event.authentication_method)
    else:
        event.effective_assurance = None
        event.attempted_assurance = None

    return event
