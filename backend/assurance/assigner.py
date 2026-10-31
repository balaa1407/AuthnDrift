"""
AuthDrift: Assigner module (backward compatibility wrapper).
Maintains seamless compatibility with existing callers while delegating to assurance_assignment.
"""

from backend.models.assurance import AssuranceLevel
from backend.assurance.assurance_assignment import (
    assign_assurance,
    assign_event_assurance,
    get_assurance_justification,
    is_high_assurance
)

__all__ = [
    "assign_assurance",
    "assign_event_assurance",
    "AssuranceLevel",
    "get_assurance_justification",
    "is_high_assurance"
]
