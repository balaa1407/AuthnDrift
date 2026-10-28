"""
AuthDrift: Detector module (backward compatibility wrapper).
Maintains seamless compatibility with existing callers while delegating to DriftDetector.
"""

from typing import List
from backend.models.event import AuthenticationEvent
from backend.models.detection import DriftResult
from backend.detection.drift_detector import DriftDetector

_DEFAULT_DETECTOR = DriftDetector()


def detect_drift(journey: List[AuthenticationEvent]) -> DriftResult:
    """
    Backward-compatible wrapper for drift detection.
    """
    return _DEFAULT_DETECTOR.detect_drift(journey)


__all__ = ["detect_drift", "DriftDetector"]
