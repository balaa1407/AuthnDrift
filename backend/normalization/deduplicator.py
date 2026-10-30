"""
AuthDrift: Event Deduplication.
Prevents duplicate normalized events from being ingested repeatedly when logs
are re-scanned or polled from identity provider event streams.
"""

from typing import Iterable, List, Set
from backend.models.event import AuthenticationEvent


class EventDeduplicator:
    """
    Stateful deduplicator tracking seen event identifiers.
    """

    def __init__(self, max_capacity: int = 50000):
        self._seen_ids: Set[str] = set()
        self._max_capacity = max_capacity

    def is_duplicate(self, event_id: str) -> bool:
        """Checks whether the event_id has already been processed."""
        if not event_id:
            return False
        return event_id in self._seen_ids

    def mark_seen(self, event_id: str) -> None:
        """Records the event_id as processed."""
        if not event_id:
            return
        if len(self._seen_ids) >= self._max_capacity:
            # Defensive eviction of oldest items when capacity is reached
            self._seen_ids.clear()
        self._seen_ids.add(event_id)

    def filter_duplicates(self, events: Iterable[AuthenticationEvent]) -> List[AuthenticationEvent]:
        """
        Filters a collection of AuthenticationEvents, returning only unique new events.
        """
        unique_events: List[AuthenticationEvent] = []
        for event in events:
            if not self.is_duplicate(event.event_id):
                self.mark_seen(event.event_id)
                unique_events.append(event)
        return unique_events

    def reset(self) -> None:
        """Clears the deduplication state cache."""
        self._seen_ids.clear()

