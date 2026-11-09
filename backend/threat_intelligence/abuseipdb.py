"""
AuthDrift: AbuseIPDB Threat Intelligence Integration.
Queries AbuseIPDB v2 REST API to evaluate public IP reputation safely and reliably.
API Documentation: https://docs.abuseipdb.com/
"""

import logging
import os
from typing import Optional
import requests

from backend.threat_intelligence.base import (
    BaseThreatIntelligenceProvider,
    IPReputationResult,
    STATUS_CLEAN,
    STATUS_KNOWN_MALICIOUS,
    STATUS_SUSPICIOUS,
    STATUS_UNKNOWN,
)

logger = logging.getLogger("authdrift.threat_intel.abuseipdb")


class AbuseIPDBProvider(BaseThreatIntelligenceProvider):
    """
    AbuseIPDB API v2 Provider implementation.
    Safely retrieves reputation and abuse confidence scores for public IPv4/IPv6 addresses.
    Never exposes API keys in log statements.
    """

    DEFAULT_API_URL = "https://api.abuseipdb.com/api/v2/check"
    DEFAULT_TIMEOUT_SECONDS = 3.0
    DEFAULT_MAX_AGE_DAYS = 90

    def __init__(
        self,
        api_key: Optional[str] = None,
        api_url: Optional[str] = None,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        max_age_days: int = DEFAULT_MAX_AGE_DAYS,
        malicious_threshold: int = 50,
        suspicious_threshold: int = 20,
    ):
        self._api_key = api_key or os.getenv("ABUSEIPDB_API_KEY", "").strip()
        self._api_url = api_url or os.getenv("ABUSEIPDB_API_URL", self.DEFAULT_API_URL)
        self.timeout = timeout
        self.max_age_days = max_age_days
        self.malicious_threshold = malicious_threshold
        self.suspicious_threshold = suspicious_threshold

        if not self._api_key:
            logger.info("AbuseIPDB API key not configured (ABUSEIPDB_API_KEY). Live external lookups disabled.")
        else:
            masked_key = self._api_key[:4] + "..." + self._api_key[-4:] if len(self._api_key) > 8 else "***"
            logger.info("AbuseIPDBProvider initialized with key: %s", masked_key)

    @property
    def provider_name(self) -> str:
        return "AbuseIPDB"

    @property
    def is_configured(self) -> bool:
        """Returns True if an API key is present."""
        return bool(self._api_key)

    def check_ip(self, ip_address: str) -> IPReputationResult:
        """
        Executes an HTTP request to AbuseIPDB check endpoint.
        Returns a structured IPReputationResult, never raises uncaught network exceptions.
        """
        if not self.is_configured:
            return IPReputationResult(
                ip_address=ip_address,
                provider=self.provider_name,
                status=STATUS_UNKNOWN,
            )

        headers = {
            "Key": self._api_key,
            "Accept": "application/json",
            "User-Agent": "AuthDrift-ThreatIntel/1.0",
        }
        params = {
            "ipAddress": ip_address,
            "maxAgeInDays": self.max_age_days,
            "verbose": True,
        }

        try:
            logger.debug("Dispatching reputation check to AbuseIPDB for IP: %s", ip_address)
            response = requests.get(
                self._api_url,
                headers=headers,
                params=params,
                timeout=self.timeout,
            )

            if response.status_code == 200:
                body = response.json()
                data = body.get("data", {})
                return self._parse_successful_response(ip_address, data)

            if response.status_code == 429:
                logger.warning("AbuseIPDB rate limit exceeded (HTTP 429) for IP %s", ip_address)
                return IPReputationResult(
                    ip_address=ip_address,
                    provider=self.provider_name,
                    status=STATUS_UNKNOWN,
                )

            if response.status_code in (401, 403):
                logger.error("AbuseIPDB authentication failed (HTTP %s). Check ABUSEIPDB_API_KEY configuration.", response.status_code)
                return IPReputationResult(
                    ip_address=ip_address,
                    provider=self.provider_name,
                    status=STATUS_UNKNOWN,
                )

            logger.warning("AbuseIPDB returned unexpected HTTP status %s for IP %s", response.status_code, ip_address)
            return IPReputationResult(
                ip_address=ip_address,
                provider=self.provider_name,
                status=STATUS_UNKNOWN,
            )

        except requests.Timeout:
            logger.warning("Timeout (%ss) while querying AbuseIPDB for IP: %s", self.timeout, ip_address)
            return IPReputationResult(
                ip_address=ip_address,
                provider=self.provider_name,
                status=STATUS_UNKNOWN,
            )
        except requests.RequestException as e:
            logger.warning("Network failure during AbuseIPDB check for IP %s: %s", ip_address, str(e))
            return IPReputationResult(
                ip_address=ip_address,
                provider=self.provider_name,
                status=STATUS_UNKNOWN,
            )
        except Exception as e:
            logger.error("Unexpected error parsing AbuseIPDB response for IP %s: %s", ip_address, str(e))
            return IPReputationResult(
                ip_address=ip_address,
                provider=self.provider_name,
                status=STATUS_UNKNOWN,
            )

    def _parse_successful_response(self, ip_address: str, data: dict) -> IPReputationResult:
        score = data.get("abuseConfidenceScore")
        try:
            score_int = int(score) if score is not None else None
        except (ValueError, TypeError):
            score_int = None

        reports = data.get("totalReports")
        try:
            reports_int = int(reports) if reports is not None else None
        except (ValueError, TypeError):
            reports_int = None

        if score_int is not None:
            if score_int >= self.malicious_threshold:
                status = STATUS_KNOWN_MALICIOUS
            elif score_int >= self.suspicious_threshold:
                status = STATUS_SUSPICIOUS
            else:
                status = STATUS_CLEAN
        else:
            status = STATUS_UNKNOWN

        return IPReputationResult(
            ip_address=ip_address,
            provider=self.provider_name,
            status=status,
            abuse_confidence_score=score_int,
            total_reports=reports_int,
            last_reported_at=data.get("lastReportedAt"),
            country_code=data.get("countryCode"),
            usage_type=data.get("usageType"),
            isp=data.get("isp"),
            domain=data.get("domain"),
            is_whitelisted=data.get("isWhitelisted"),
        )

