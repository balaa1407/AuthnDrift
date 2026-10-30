"""
AuthDrift: Base Event Normalizer Interface.
Defines the abstract contract for converting raw identity provider event logs
into the common AuthenticationEvent normalized schema.
"""

from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from backend.models.event import AuthenticationEvent


class BaseEventNormalizer(ABC):
    """
    Abstract base normalizer for vendor-neutral identity provider logs.
    Preserves raw event access for debugging without compromising normalized contracts.
    """

    def __init__(self):
        self._raw_cache: Dict[str, Dict[str, Any]] = {}

    @abstractmethod
    def normalize_single(self, raw_event: Dict[str, Any]) -> Optional[AuthenticationEvent]:
        """
        Transforms a single raw event dictionary into a normalized AuthenticationEvent.
        Returns None if the event cannot be mapped or should be skipped.
        """
        raise NotImplementedError

    def normalize_batch(self, raw_events: List[Dict[str, Any]]) -> List[AuthenticationEvent]:
        """
        Transforms a batch of raw event dictionaries, discarding unparseable events safely.
        """
        normalized: List[AuthenticationEvent] = []
        for raw in raw_events:
            if not isinstance(raw, dict):
                continue
            event = self.normalize_single(raw)
            if event:
                normalized.append(event)
        return normalized

    def get_raw_event(self, event_id: str) -> Optional[Dict[str, Any]]:
        """
        Retrieves the original raw event for debugging and forensic inspection.
        """
        return self._raw_cache.get(event_id)

    def _store_raw(self, event_id: str, raw_event: Dict[str, Any]) -> None:
        """Stores the raw event in the debug cache."""
        if event_id:
            self._raw_cache[event_id] = raw_event

    @staticmethod
    def _parse_timestamp(val: Any) -> datetime:
        """
        Safely parses timestamps across milliseconds epoch, seconds epoch, and ISO-8601 strings.
        Ensures resulting datetime is timezone-aware in UTC.
        """
        if isinstance(val, datetime):
            if val.tzinfo is None:
                return val.replace(tzinfo=timezone.utc)
            return val.astimezone(timezone.utc)

        if isinstance(val, (int, float)):
            # Distinguish milliseconds (Keycloak epoch: > 10^11) vs seconds
            if val > 1e11:
                return datetime.fromtimestamp(val / 1000.0, tz=timezone.utc)
            return datetime.fromtimestamp(val, tz=timezone.utc)

        if isinstance(val, str):
            val_clean = val.strip()
            # Try numeric string
            try:
                numeric_val = float(val_clean)
                return BaseEventNormalizer._parse_timestamp(numeric_val)
            except ValueError:
                pass

            # Try ISO-8601 string formats
            try:
                # Handle 'Z' suffix in Python < 3.11 or standard ISO format
                if val_clean.endswith("Z"):
                    val_clean = val_clean[:-1] + "+00:00"
                dt = datetime.fromisoformat(val_clean)
                if dt.tzinfo is None:
                    return dt.replace(tzinfo=timezone.utc)
                return dt.astimezone(timezone.utc)
            except Exception:
                pass

        # Fallback to current UTC time if unavailable
        return datetime.now(timezone.utc)

