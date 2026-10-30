"""
AuthDrift Integration Tests: Event Normalization Layer.
Validates:
- Keycloak raw event normalization into common AuthenticationEvent schema
- Safe handling of missing optional fields (no fabricated context)
- Deduplication of re-processed events
- Malformed inputs and edge cases
"""

from datetime import datetime, timezone
import pytest
from backend.models.event import AuthenticationEvent
from backend.normalization.keycloak import KeycloakEventNormalizer
from backend.normalization.deduplicator import EventDeduplicator


class TestEventNormalization:
    def setup_method(self):
        self.normalizer = KeycloakEventNormalizer()
        self.deduplicator = EventDeduplicator()

    def test_normalize_keycloak_passkey_success(self):
        raw = {
            "id": "kc-evt-100",
            "time": 1730300400000,
            "type": "LOGIN",
            "userId": "usr-uuid-001",
            "sessionId": "sess-xyz",
            "ipAddress": "192.168.1.50",
            "details": {
                "username": "alice",
                "auth_method": "webauthn",
                "device_id": "macbook-air",
                "location": "Bangalore, IN",
                "authenticator_id": "yubikey-5c"
            }
        }
        event = self.normalizer.normalize_single(raw)
        assert isinstance(event, AuthenticationEvent)
        assert event.event_id == "kc-evt-100"
        assert event.user_id == "alice"
        assert event.event_type == "LOGIN"
        assert event.authentication_method == "passkey"
        assert event.outcome == "SUCCESS"
        assert event.device_id == "macbook-air"
        assert event.location == "Bangalore, IN"
        assert event.authenticator_id == "yubikey-5c"
        assert event.session_id == "sess-xyz"
        assert event.source_provider == "keycloak"
        assert event.timestamp.tzinfo is not None

    def test_normalize_keycloak_password_failure(self):
        raw = {
            "id": "kc-evt-101",
            "time": 1730300410000,
            "type": "LOGIN_ERROR",
            "details": {
                "username": "bob",
                "auth_method": "password",
                "error": "invalid_user_credentials"
            }
        }
        event = self.normalizer.normalize_single(raw)
        assert event.user_id == "bob"
        assert event.authentication_method == "password"
        assert event.outcome == "FAILURE"
        assert event.device_id is None
        assert event.location is None
        assert event.authenticator_id is None
        assert event.session_id is None

    def test_missing_optional_fields_no_fabrication(self):
        """Verify that when optional fields are absent, they are strictly set to None."""
        raw = {
            "id": "kc-evt-102",
            "time": 1730300420000,
            "type": "LOGIN",
            "details": {
                "username": "heidi"
            }
        }
        event = self.normalizer.normalize_single(raw)
        assert event.user_id == "heidi"
        assert event.device_id is None
        assert event.location is None
        assert event.authenticator_id is None
        assert event.session_id is None
        assert event.authentication_method == "password"  # Keycloak default primary credential

    def test_raw_event_preserved_for_debugging(self):
        raw = {"id": "kc-evt-debug", "time": 1730300430000, "type": "LOGIN", "details": {"username": "frank"}}
        event = self.normalizer.normalize_single(raw)
        cached = self.normalizer.get_raw_event(event.event_id)
        assert cached == raw

    def test_malformed_events_handled_gracefully(self):
        assert self.normalizer.normalize_single(None) is None
        assert self.normalizer.normalize_single("corrupted_string") is None
        assert self.normalizer.normalize_batch([None, {}, "invalid"]) == [{}] or len(self.normalizer.normalize_batch([None, "invalid"])) == 0

    def test_event_deduplication(self):
        raw = {
            "id": "kc-evt-dup",
            "time": 1730300400000,
            "type": "LOGIN",
            "details": {"username": "alice", "auth_method": "passkey"}
        }
        event1 = self.normalizer.normalize_single(raw)
        event2 = self.normalizer.normalize_single(raw)

        filtered = self.deduplicator.filter_duplicates([event1, event2])
        assert len(filtered) == 1
        assert filtered[0].event_id == "kc-evt-dup"

