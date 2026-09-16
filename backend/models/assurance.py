from enum import Enum

class AssuranceLevel(Enum):
    """
    Relative assurance levels for authentication methods.
    Ordered by relative strength for easy comparison (LOW < MEDIUM < HIGH).
    """
    LOW = 1
    MEDIUM = 2
    HIGH = 3
