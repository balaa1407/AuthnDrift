"""
AuthDrift: IP Threat Intelligence Interface and Data Models.
Provides a modular abstraction for external IP reputation providers.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Dict, Optional


# Standard Reputation Status Constants
STATUS_KNOWN_MALICIOUS = "KNOWN_MALICIOUS"
STATUS_SUSPICIOUS = "SUSPICIOUS"
STATUS_CLEAN = "CLEAN"
STATUS_PRIVATE = "PRIVATE"
STATUS_UNKNOWN = "UNKNOWN"


@dataclass
class IPReputationResult:
    """
    Standardized vendor-neutral IP reputation result.
    """
    ip_address: Optional[str]
    provider: str
    status: str  # KNOWN_MALICIOUS, SUSPICIOUS, CLEAN, PRIVATE, UNKNOWN
    abuse_confidence_score: Optional[int] = None
    total_reports: Optional[int] = None
    last_reported_at: Optional[str] = None
    country_code: Optional[str] = None
    usage_type: Optional[str] = None
    isp: Optional[str] = None
    domain: Optional[str] = None
    is_whitelisted: Optional[bool] = None

    def to_dict(self) -> Dict[str, Any]:
        """Serializes reputation result to JSON-compatible dictionary."""
        return {
            "provider": self.provider,
            "ip_address": self.ip_address,
            "status": self.status,
            "abuse_confidence_score": self.abuse_confidence_score,
            "total_reports": self.total_reports,
            "last_reported_at": self.last_reported_at,
            "country_code": self.country_code,
            "usage_type": self.usage_type,
            "isp": self.isp,
            "domain": self.domain,
            "is_whitelisted": self.is_whitelisted,
        }


class BaseThreatIntelligenceProvider(ABC):
    """
    Abstract interface for IP Threat Intelligence lookups.
    """

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Name of the provider (e.g. AbuseIPDB)."""
        raise NotImplementedError

    @abstractmethod
    def check_ip(self, ip_address: str) -> IPReputationResult:
        """
        Queries the external threat intelligence service for an IP address.
        Must return an IPReputationResult even on failure (with status=UNKNOWN).
        Must never throw unhandled network exceptions.
        """
        raise NotImplementedError

