"""
AuthDrift: Risk Configuration and Weightings.
Configurable parameters for transparent, reproducible risk scoring.
"""

from dataclasses import dataclass
from backend.models.detection import RiskSeverity


@dataclass
class RiskEngineConfig:
    """
    Configurable scoring weights and severity thresholds for risk assessment.
    """
    # Assurance Downgrade Weights
    weight_downgrade_high_to_low: int = 40
    weight_downgrade_high_to_medium: int = 20
    weight_downgrade_medium_to_low: int = 15

    # Behavioral Failure Pattern Weights
    weight_failed_strong_preceding: int = 15
    weight_repeated_failures: int = 10  # 2 or more failures

    # Contextual Signal Weights
    weight_new_device: int = 20
    weight_location_change: int = 15
    weight_authenticator_registered: int = 25  # High-priority persistence indicator

    # Severity Threshold Boundaries
    threshold_low_max: int = 29
    threshold_medium_max: int = 59
    threshold_high_max: int = 79
    # 80-100 is CRITICAL

    def get_severity(self, score: int) -> RiskSeverity:
        """
        Maps a 0-100 numerical score into a RiskSeverity tier.
        """
        if score <= self.threshold_low_max:
            return RiskSeverity.LOW
        elif score <= self.threshold_medium_max:
            return RiskSeverity.MEDIUM
        elif score <= self.threshold_high_max:
            return RiskSeverity.HIGH
        else:
            return RiskSeverity.CRITICAL
