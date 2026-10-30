"""
AuthDrift Integration Tests: Authentication Journey Reconstruction.
Validates:
- Grouping events by user and session
- Chronological ordering of out-of-order events
- Inactivity windowing and session boundaries
- Cross-user isolation
"""

from datetime import datetime, timezone, timedelta
import pytest
from backend.models.event import AuthenticationEvent
from backend.journey.reconstructor import JourneyReconstructor


def make_ev(user_id: str, delta_s: int, session_id: str = None, method: str = "password", outcome: str = "SUCCESS"):
    base = datetime(2026, 10, 30, 14, 0, 0, tzinfo=timezone.utc)
    return AuthenticationEvent(
        event_id=f"evt-{user_id}-{delta_s}",
        user_id=user_id,
        timestamp=base + timedelta(seconds=delta_s),
        event_type="LOGIN",
        authentication_method=method,
        outcome=outcome,
        session_id=session_id
    )


class TestJourneyReconstruction:
    def setup_method(self):
        # 10 minute session window for test predictability
        self.reconstructor = JourneyReconstructor(session_timeout_seconds=600)

    def test_chronological_ordering_of_out_of_order_events(self):
        """Events arriving out of order must be ordered chronologically."""
        ev1 = make_ev("alice", delta_s=0, method="passkey", outcome="FAILURE")
        ev2 = make_ev("alice", delta_s=15, method="password", outcome="SUCCESS")
        ev3 = make_ev("alice", delta_s=30, method="webauthn", outcome="SUCCESS")

        # Ingest in reversed order
        journeys = self.reconstructor.reconstruct_journeys([ev3, ev1, ev2])

        assert len(journeys) == 1
        j = journeys[0]
        assert j.user_id == "alice"
        assert len(j.events) == 3
        assert j.events[0].event_id == ev1.event_id
        assert j.events[1].event_id == ev2.event_id
        assert j.events[2].event_id == ev3.event_id

    def test_grouping_multiple_users_cross_user_isolation(self):
        """Events for different users must be partitioned into separate journeys."""
        ev_alice1 = make_ev("alice", delta_s=0)
        ev_bob1 = make_ev("bob", delta_s=5)
        ev_alice2 = make_ev("alice", delta_s=10)

        journeys = self.reconstructor.reconstruct_journeys([ev_alice1, ev_bob1, ev_alice2])
        assert len(journeys) == 2

        user_ids = {j.user_id for j in journeys}
        assert user_ids == {"alice", "bob"}

        alice_j = next(j for j in journeys if j.user_id == "alice")
        assert len(alice_j.events) == 2

        bob_j = next(j for j in journeys if j.user_id == "bob")
        assert len(bob_j.events) == 1

    def test_session_boundary_distinction(self):
        """Events for same user with different session_ids are grouped into distinct journeys."""
        ev_s1_a = make_ev("carol", delta_s=0, session_id="sess-A")
        ev_s1_b = make_ev("carol", delta_s=10, session_id="sess-A")
        ev_s2_a = make_ev("carol", delta_s=20, session_id="sess-B")

        journeys = self.reconstructor.reconstruct_journeys([ev_s1_a, ev_s2_a, ev_s1_b])
        assert len(journeys) == 2

        s_ids = {j.session_id for j in journeys}
        assert s_ids == {"sess-A", "sess-B"}

    def test_inactivity_window_timeout(self):
        """Events separated by more than session_timeout are split into separate journeys."""
        ev1 = make_ev("dave", delta_s=0)
        # 15 minutes later (exceeds 10-minute timeout)
        ev2 = make_ev("dave", delta_s=900)

        journeys = self.reconstructor.reconstruct_journeys([ev1, ev2])
        assert len(journeys) == 2
        assert len(journeys[0].events) == 1
        assert len(journeys[1].events) == 1

    def test_empty_event_list_handling(self):
        assert self.reconstructor.reconstruct_journeys([]) == []
        assert self.reconstructor.reconstruct_journeys([None]) == []

