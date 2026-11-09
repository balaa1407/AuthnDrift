"""
AuthDrift: IP Reputation Service with IP Validation, Caching, and Safe Failure.
Coordinates threat intelligence lookups with local IP address validation
and in-memory TTL caching to avoid unnecessary external queries.
"""

from datetime import datetime, timezone
import ipaddress
import logging
import os
import threading
from typing import Dict, Optional, Tuple

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

logger = logging.getLogger("authdrift.threat_intel.service")


class IPReputationService:
    """
    High-level threat intelligence service for AuthDrift.
    - Validates IP addresses before forwarding to external providers.
    - Filters out private, loopback, and reserved IPs locally.
    - Maintains an in-memory thread-safe cache with configurable TTL.
    - Fails open/gracefully without interrupting core authentication journey analysis.
    """

    DEFAULT_CACHE_TTL_SECONDS = 86400  # 24 hours

    def __init__(
        self,
        provider: Optional[BaseThreatIntelligenceProvider] = None,
        cache_ttl_seconds: Optional[int] = None,
        enabled: Optional[bool] = None,
    ):
        self.provider = provider or AbuseIPDBProvider()

        if cache_ttl_seconds is not None:
            self.cache_ttl = cache_ttl_seconds
        else:
            try:
                self.cache_ttl = int(os.getenv("AUTH_DRIFT_IP_CACHE_TTL", str(self.DEFAULT_CACHE_TTL_SECONDS)))
            except ValueError:
                self.cache_ttl = self.DEFAULT_CACHE_TTL_SECONDS

        if enabled is not None:
            self.enabled = enabled
        else:
            env_val = os.getenv("AUTH_DRIFT_ENABLE_THREAT_INTEL", "true").strip().lower()
            self.enabled = env_val not in ("false", "0", "no", "off")

        # Cache structure: {ip_str: (IPReputationResult, cached_at_epoch)}
        self._cache: Dict[str, Tuple[IPReputationResult, float]] = {}
        self._lock = threading.Lock()

    @staticmethod
    def is_public_ip(ip_str: Optional[str]) -> Tuple[bool, str]:
        """
        Validates an IP string using python's ipaddress module.
        Returns (is_public: bool, reason: str).
        """
        if not ip_str or not isinstance(ip_str, str):
            return False, "MISSING"

        cleaned_ip = ip_str.strip()
        if not cleaned_ip:
            return False, "EMPTY"

        # Strip brackets if IPv6 with brackets e.g. [2001:db8::1]
        cleaned_ip = cleaned_ip.strip("[]")

        try:
            ip_obj = ipaddress.ip_address(cleaned_ip)
        except ValueError:
            return False, "INVALID"

        # Check for non-public IP categories
        if (
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_reserved
            or ip_obj.is_multicast
            or ip_obj.is_link_local
            or ip_obj.is_unspecified
        ):
            return False, "PRIVATE"

        return True, "PUBLIC"

    def get_ip_reputation(self, ip_address: Optional[str]) -> IPReputationResult:
        """
        Retrieves IP reputation safely:
        1. If service is disabled, returns UNKNOWN.
        2. Validates IP: if private/reserved, returns PRIVATE immediately.
        3. Checks TTL cache: if hit, returns cached result.
        4. Queries provider: on success, stores in cache; on temporary error, does not cache.
        """
        if not ip_address:
            return IPReputationResult(
                ip_address=None,
                provider=self.provider.provider_name if self.provider else "ThreatIntelligence",
                status=STATUS_UNKNOWN,
            )

        cleaned_ip = str(ip_address).strip().strip("[]")

        # Step 1: Validate IP structure and scope
        is_public, reason = self.is_public_ip(cleaned_ip)
        if not is_public:
            if reason == "PRIVATE":
                logger.debug("IP %s is private/loopback/reserved. Skipping external lookup.", cleaned_ip)
                return IPReputationResult(
                    ip_address=cleaned_ip,
                    provider=self.provider.provider_name if self.provider else "LocalValidator",
                    status=STATUS_PRIVATE,
                    abuse_confidence_score=0,
                    total_reports=0,
                )
            logger.debug("IP %s validation result: %s. Marked as UNKNOWN.", cleaned_ip, reason)
            return IPReputationResult(
                ip_address=cleaned_ip,
                provider=self.provider.provider_name if self.provider else "LocalValidator",
                status=STATUS_UNKNOWN,
            )

        if not self.enabled:
            logger.debug("Threat intelligence lookup disabled by configuration.")
            return IPReputationResult(
                ip_address=cleaned_ip,
                provider=self.provider.provider_name if self.provider else "ThreatIntelligence",
                status=STATUS_UNKNOWN,
            )

        # Step 2: Check in-memory cache
        now_epoch = datetime.now(timezone.utc).timestamp()
        with self._lock:
            if cleaned_ip in self._cache:
                cached_result, cached_at = self._cache[cleaned_ip]
                if now_epoch - cached_at < self.cache_ttl:
                    logger.debug("Cache hit for IP %s (status: %s)", cleaned_ip, cached_result.status)
                    return cached_result
                else:
                    logger.debug("Cache expired for IP %s", cleaned_ip)
                    del self._cache[cleaned_ip]

        # Step 3: Query external provider safely
        try:
            result = self.provider.check_ip(cleaned_ip)
        except Exception as e:
            logger.error("Threat intelligence provider raised unexpected error for IP %s: %s", cleaned_ip, str(e))
            result = IPReputationResult(
                ip_address=cleaned_ip,
                provider=self.provider.provider_name if self.provider else "ThreatIntelligence",
                status=STATUS_UNKNOWN,
            )

        # Step 4: Cache only definitive results (not transient UNKNOWN failures)
        if result.status in (STATUS_KNOWN_MALICIOUS, STATUS_SUSPICIOUS, STATUS_CLEAN, STATUS_PRIVATE):
            with self._lock:
                self._cache[cleaned_ip] = (result, now_epoch)
                logger.debug("Cached reputation for IP %s (status: %s, score: %s)", cleaned_ip, result.status, result.abuse_confidence_score)
        else:
            logger.info("Not caching transient UNKNOWN reputation result for IP %s", cleaned_ip)

        return result

    def clear_cache(self) -> None:
        """Purges all cached entries."""
        with self._lock:
            self._cache.clear()

    @property
    def cache_size(self) -> int:
        """Returns the number of cached items."""
        with self._lock:
            return len(self._cache)

