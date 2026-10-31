"""
AuthDrift: Unit and Integration Tests for Location Baselines, IP Separation,
and Authenticator Registration vs. Usage.
"""

from datetime import datetime, timezone, timedelta
import pytest
from backend.models.event import AuthenticationEvent
from backend.correlation.location_profiler import LocationProfiler, LocationStatus, UserLocationProfile
from backend.correlation.context_analyzer import ContextAnalyzer
from backend.normalization.keycloak import KeycloakEventNormalizer
from backend.normalization.okta import OktaEventNormalizer


def make_test_event(
    user_id: str,
    outcome: str = "SUCCESS",
    location: str = None,
    ip_address: str = None,
    device_id: str = None,
    authenticator_id: str = None,
    event_type: str = "LOGIN",
    delta_sec: int = 0
) -> AuthenticationEvent:
    base = datetime(2026, 10, 30, 10, 0, 0, tzinfo=timezone.utc)
    return AuthenticationEvent(
        event_id=f"evt-{user_id}-{delta_sec}",
        user_id=user_id,
        timestamp=base + timedelta(seconds=delta_sec),
        event_type=event_type,
        authentication_method="password",
        outcome=outcome,
        device_id=device_id,
        location=location,
        ip_address=ip_address,
        authenticator_id=authenticator_id
    )


class TestLocationProfiler:
    def test_insufficient_history_returns_unknown(self):
        """If fewer than min_successful_observations exist, baseline is not established -> UNKNOWN."""
        profiler = LocationProfiler(min_successful_observations=2)
        # Only 1 successful observation
        history = [
            make_test_event("user-a", outcome="SUCCESS", location="Bangalore, IN", delta_sec=0)
        ]
        profiler.build_profiles(history)

        status, primary = profiler.evaluate_location("user-a", "Bangalore, IN")
        assert status == LocationStatus.UNKNOWN
        assert primary is None

    def test_failed_events_do_not_establish_baseline(self):
        """Only successful authentications establish historical baseline; failures are ignored."""
        profiler = LocationProfiler(min_successful_observations=2)
        history = [
            make_test_event("user-b", outcome="FAILURE", location="Berlin, DE", delta_sec=0),
            make_test_event("user-b", outcome="FAILURE", location="Berlin, DE", delta_sec=10),
            make_test_event("user-b", outcome="FAILURE", location="Berlin, DE", delta_sec=20),
        ]
        profiler.build_profiles(history)

        profile = profiler.get_profile("user-b")
        assert profile is None

        status, primary = profiler.evaluate_location("user-b", "Berlin, DE")
        assert status == LocationStatus.UNKNOWN
        assert primary is None

    def test_deterministic_primary_location_mode(self):
        """Primary location is deterministically the most frequently observed successful location."""
        profiler = LocationProfiler(min_successful_observations=2)
        history = [
            make_test_event("user-c", outcome="SUCCESS", location="London, UK", delta_sec=0),
            make_test_event("user-c", outcome="SUCCESS", location="London, UK", delta_sec=10),
            make_test_event("user-c", outcome="SUCCESS", location="Paris, FR", delta_sec=20),
        ]
        profiler.build_profiles(history)

        profile = profiler.get_profile("user-c")
        assert profile is not None
        assert profile.is_baseline_established is True
        assert profile.primary_location == "London, UK"
        assert "London, UK" in profile.known_locations
        assert "Paris, FR" in profile.known_locations

        # Known location evaluation
        status_london, p1 = profiler.evaluate_location("user-c", "London, UK")
        assert status_london == LocationStatus.KNOWN
        assert p1 == "London, UK"

        status_paris, p2 = profiler.evaluate_location("user-c", "Paris, FR")
        assert status_paris == LocationStatus.KNOWN
        assert p2 == "London, UK"

        # New location evaluation
        status_tokyo, p3 = profiler.evaluate_location("user-c", "Tokyo, JP")
        assert status_tokyo == LocationStatus.NEW
        assert p3 == "London, UK"

    def test_missing_location_evaluates_to_unknown(self):
        """When current event has no location data, evaluation returns UNKNOWN."""
        profiler = LocationProfiler(min_successful_observations=2)
        history = [
            make_test_event("user-d", outcome="SUCCESS", location="Sydney, AU", delta_sec=0),
            make_test_event("user-d", outcome="SUCCESS", location="Sydney, AU", delta_sec=10),
        ]
        profiler.build_profiles(history)

        status_none, primary = profiler.evaluate_location("user-d", None)
        assert status_none == LocationStatus.UNKNOWN
        assert primary is None

        status_empty, primary2 = profiler.evaluate_location("user-d", "   ")
        assert status_empty == LocationStatus.UNKNOWN

    def test_per_user_isolation(self):
        """Each user has an independent profile; Alice's baseline never applies to Bob."""
        profiler = LocationProfiler(min_successful_observations=2)
        history = [
            make_test_event("alice", outcome="SUCCESS", location="Bangalore, IN", delta_sec=0),
            make_test_event("alice", outcome="SUCCESS", location="Bangalore, IN", delta_sec=10),
            make_test_event("bob", outcome="SUCCESS", location="San Francisco, US", delta_sec=0),
            make_test_event("bob", outcome="SUCCESS", location="San Francisco, US", delta_sec=10),
        ]
        profiler.build_profiles(history)

        alice_prof = profiler.get_profile("alice")
        bob_prof = profiler.get_profile("bob")
        assert alice_prof.primary_location == "Bangalore, IN"
        assert bob_prof.primary_location == "San Francisco, US"

        # Bangalore is KNOWN for Alice, but NEW for Bob
        status_a, _ = profiler.evaluate_location("alice", "Bangalore, IN")
        status_b, _ = profiler.evaluate_location("bob", "Bangalore, IN")
        assert status_a == LocationStatus.KNOWN
        assert status_b == LocationStatus.NEW


class TestIPSeparationAndNormalization:
    def test_keycloak_normalizer_separates_ip_and_location(self):
        """Keycloak normalizer extracts ip_address into ip_address and never substitutes for location."""
        normalizer = KeycloakEventNormalizer()
        raw_event = {
            "id": "kc-ip-test-01",
            "time": 1793368800000,
            "type": "LOGIN",
            "ipAddress": "198.51.100.44",
            "details": {
                "username": "tester",
                "auth_method": "password",
                # Note: No location in details
            }
        }
        event = normalizer.normalize_single(raw_event)
        assert event is not None
        assert event.ip_address == "198.51.100.44"
        # Location MUST be None, not substituted with IP!
        assert event.location is None

    def test_keycloak_normalizer_with_both_ip_and_location(self):
        """Both IP and geographic location are stored in their respective distinct fields."""
        normalizer = KeycloakEventNormalizer()
        raw_event = {
            "id": "kc-ip-test-02",
            "time": 1793368800000,
            "type": "LOGIN",
            "ipAddress": "203.0.113.8",
            "details": {
                "username": "tester",
                "auth_method": "password",
                "location": "Toronto, Canada"
            }
        }
        event = normalizer.normalize_single(raw_event)
        assert event is not None
        assert event.ip_address == "203.0.113.8"
        assert event.location == "Toronto, Canada"

    def test_okta_normalizer_separates_ip_and_location(self):
        """Okta normalizer extracts client.ipAddress into ip_address and never substitutes for location."""
        normalizer = OktaEventNormalizer()
        raw_event = {
            "uuid": "okta-ip-test-01",
            "published": "2026-10-30T14:00:00.000Z",
            "eventType": "user.authentication.authenticate",
            "actor": {"id": "usr-01", "alternateId": "test@domain.com"},
            "client": {
                "ipAddress": "192.0.2.1",
                # No geographicalContext
            }
        }
        event = normalizer.normalize_single(raw_event)
        assert event is not None
        assert event.ip_address == "192.0.2.1"
        assert event.location is None

    def test_okta_normalizer_with_both_ip_and_location(self):
        """Okta normalizer extracts both geographicalContext and IP separately."""
        normalizer = OktaEventNormalizer()
        raw_event = {
            "uuid": "okta-ip-test-02",
            "published": "2026-10-30T14:00:00.000Z",
            "eventType": "user.authentication.authenticate",
            "actor": {"id": "usr-01", "alternateId": "test@domain.com"},
            "client": {
                "ipAddress": "192.0.2.1",
                "geographicalContext": {"city": "Zurich", "country": "Switzerland"}
            }
        }
        event = normalizer.normalize_single(raw_event)
        assert event is not None
        assert event.ip_address == "192.0.2.1"
        assert event.location == "Zurich, Switzerland"


class TestAuthenticatorRegistrationVsUsage:
    def setup_method(self):
        self.analyzer = ContextAnalyzer()

    def test_authenticator_id_in_login_does_not_infer_registration(self):
        """Merely using an authenticator during login must NOT set authenticator_registered = True."""
        journey = [
            make_test_event(
                "user-auth-01",
                outcome="SUCCESS",
                authenticator_id="fido2-yubikey-sec-01",
                event_type="LOGIN"
            )
        ]
        evidence = self.analyzer.analyze_journey_context(
            journey,
            known_authenticators={"different-yubikey-02"}
        )
        assert evidence.authenticator_id == "fido2-yubikey-sec-01"
        # Must NOT be marked as registered!
        assert evidence.authenticator_registered is not True
        assert not any("registered" in note.lower() for note in evidence.evidence_notes)

    def test_explicit_registration_event_sets_authenticator_registered(self):
        """An explicit registration event (e.g. REGISTER_AUTHENTICATOR) sets authenticator_registered = True."""
        journey = [
            make_test_event("user-auth-02", outcome="SUCCESS", event_type="LOGIN", delta_sec=0),
            make_test_event(
                "user-auth-02",
                outcome="SUCCESS",
                authenticator_id="fido2-new-token-99",
                event_type="REGISTER_AUTHENTICATOR",
                delta_sec=20
            )
        ]
        evidence = self.analyzer.analyze_journey_context(journey)
        assert evidence.authenticator_registered is True
        assert evidence.authenticator_id == "fido2-new-token-99"
        assert any("explicit authenticator registration" in note.lower() for note in evidence.evidence_notes)

