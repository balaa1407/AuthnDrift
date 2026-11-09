"""
AuthDrift: Threat Intelligence Subsystem.
"""

from backend.threat_intelligence.base import (
    BaseThreatIntelligenceProvider,
    IPReputationResult,
    STATUS_CLEAN,
    STATUS_KNOWN_MALICIOUS,
    STATUS_PRIVATE,
    STATUS_SUSPICIOUS,
    STATUS_UNKNOWN,
)
from backend.threat_intelligence.abuseipdb import AbuseIPDBProvider
from backend.threat_intelligence.reputation_service import IPReputationService

__all__ = [
    "BaseThreatIntelligenceProvider",
    "IPReputationResult",
    "AbuseIPDBProvider",
    "IPReputationService",
    "STATUS_KNOWN_MALICIOUS",
    "STATUS_SUSPICIOUS",
    "STATUS_CLEAN",
    "STATUS_PRIVATE",
    "STATUS_UNKNOWN",
]

