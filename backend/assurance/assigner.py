"""
AuthDrift: Assigner module (backward compatibility wrapper).
Maintains seamless compatibility with existing callers while delegating to assurance_assignment.
"""

from backend.models.assurance import AssuranceLevel
from backend.assurance.assurance_assignment import assign_assurance, get_assurance_justification

__all__ = ["assign_assurance", "AssuranceLevel", "get_assurance_justification"]
