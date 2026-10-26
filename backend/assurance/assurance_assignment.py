"""
AuthDrift: Assurance Assignment Interface.
Assigns relative assurance levels to authentication methods and normalized events.
"""

from typing import Optional
from backend.models.assurance import AssuranceLevel
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
