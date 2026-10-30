"""
AuthDrift: Authentication Journey Reconstructor.
Groups normalized authentication events chronologically per user and session/window.
Produces reconstructed AuthenticationJourney structures ready for AuthDriftEngine evaluation.
"""

from collections import defaultdict
from datetime import timedelta
from typing import Dict, List, Optional
from backend.models.event import AuthenticationEvent, AuthenticationJourney


class JourneyReconstructor:
    """
    Reconstructs chronological multi-step authentication journeys.
    
    Handles:
    - Grouping by user_id and session_id (when available).
    - Session window boundaries: segments journeys if events are separated by more
      than `session_timeout_seconds` of inactivity.
    - Chronological sorting to guarantee sequence order even when logs arrive out of order.
    - Distinguishes independent authentication attempts for the same user.
    """

    DEFAULT_SESSION_TIMEOUT_SECONDS = 1800  # 30 minutes inactivity timeout

    def __init__(self, session_timeout_seconds: int = DEFAULT_SESSION_TIMEOUT_SECONDS):
        self.session_timeout = timedelta(seconds=session_timeout_seconds)

    def reconstruct_journeys(
        self,
        events: List[AuthenticationEvent]
    ) -> List[AuthenticationJourney]:
        """
        Reconstructs a list of AuthenticationJourneys from an arbitrary list of AuthenticationEvents.
        
        Guarantees:
        1. Events within a journey belong strictly to the same user.
        2. Events within a journey are sorted chronologically by timestamp.
        3. Multi-attempt sequences separated by session boundaries or inactivity windows
           are split into separate journeys.
        """
        if not events:
            return []

        # Step 1: Group events by user_id
        user_events_map: Dict[str, List[AuthenticationEvent]] = defaultdict(list)
        for event in events:
            if not isinstance(event, AuthenticationEvent):
                continue
            user_events_map[event.user_id].append(event)

        reconstructed_journeys: List[AuthenticationJourney] = []

        # Step 2: For each user, order events and split by session_id / inactivity window
        for user_id, u_events in user_events_map.items():
            # Sort all user events chronologically
            sorted_events = sorted(u_events, key=lambda e: e.timestamp)

            # Sub-group by session_id if present, or split by time delta
            journeys_for_user = self._split_user_events(user_id, sorted_events)
            reconstructed_journeys.extend(journeys_for_user)

        # Stable sort of all reconstructed journeys by the timestamp of their earliest event
        reconstructed_journeys.sort(
            key=lambda j: j.events[0].timestamp if j.events else None
        )

        return reconstructed_journeys

    def _split_user_events(
        self,
        user_id: str,
        sorted_events: List[AuthenticationEvent]
    ) -> List[AuthenticationJourney]:
        """
        Splits sorted events of a single user into distinct journeys based on session_id
        and inactivity time gaps.
        """
        if not sorted_events:
            return []

        # If explicit session_ids are present, group by session_id first
        # But handle cases where session_id is None by applying inactivity windowing
        session_groups: Dict[Optional[str], List[AuthenticationEvent]] = defaultdict(list)
        has_explicit_session_ids = any(e.session_id is not None for e in sorted_events)

        if has_explicit_session_ids:
            for ev in sorted_events:
                session_groups[ev.session_id].append(ev)

            result: List[AuthenticationJourney] = []
            for s_id, ev_list in session_groups.items():
                # Within each session_id group, also respect inactivity windows
                windowed = self._window_events(user_id, ev_list, s_id)
                result.extend(windowed)
            return result
        else:
            # No session_ids provided; window strictly by time gaps
            return self._window_events(user_id, sorted_events, session_id=None)

    def _window_events(
        self,
        user_id: str,
        events: List[AuthenticationEvent],
        session_id: Optional[str]
    ) -> List[AuthenticationJourney]:
        """
        Splits a chronological stream of events into separate journeys whenever
        the time gap between consecutive events exceeds self.session_timeout.
        """
        if not events:
            return []

        journeys: List[AuthenticationJourney] = []
        current_journey = AuthenticationJourney(user_id=user_id, session_id=session_id)
        current_journey.add_event(events[0])

        for prev_event, curr_event in zip(events[:-1], events[1:]):
            time_gap = curr_event.timestamp - prev_event.timestamp
            if time_gap > self.session_timeout:
                # Inactivity window exceeded; start a new journey
                journeys.append(current_journey)
                current_journey = AuthenticationJourney(
                    user_id=user_id,
                    session_id=curr_event.session_id or session_id
                )
            current_journey.add_event(curr_event)

        journeys.append(current_journey)
        return journeys

