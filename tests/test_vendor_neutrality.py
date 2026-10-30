"""
AuthDrift Vendor-Neutrality Tests.
Demonstrates that an alternative enterprise identity provider format (Okta System Log)
is normalized into the exact same common schema and seamlessly processed by
AuthDrift's downstream journey reconstruction and Balaa's AuthDriftEngine.
"""

import pytest
from backend.normalization.okta import OktaEventNormalizer
from backend.pipeline.pipeline import AuthDriftPipeline
from backend.models.event import AuthenticationEvent
from backend.models.detection import RiskSeverity
from keycloak.generate_keycloak_fixtures import generate_okta_fixtures


class TestVendorNeutrality:
    def setup_method(self):
        self.okta_normalizer = OktaEventNormalizer()
        self.pipeline = AuthDriftPipeline()

    def test_okta_raw_event_normalization(self):
        raw_okta = {
            "uuid": "okta-evt-123",
            "published": "2026-10-30T14:15:00.000Z",
            "eventType": "user.authentication.auth_via_mfa",
            "outcome": {"result": "FAILURE"},
            "actor": {"id": "00u123", "alternateId": "alex@company.com"},
            "client": {
                "device": "MacBookPro18,1",
                "geographicalContext": {"city": "San Francisco", "country": "United States"}
            },
            "authenticationContext": {
                "credentialProvider": "FIDO2 (WebAuthn)",
                "externalSessionId": "sess-okta-001"
            }
        }
        event = self.okta_normalizer.normalize_single(raw_okta)

        assert isinstance(event, AuthenticationEvent)
        assert event.event_id == "okta-evt-123"
        assert event.user_id == "alex@company.com"
        assert event.authentication_method == "passkey"
        assert event.outcome == "FAILURE"
        assert event.device_id == "MacBookPro18,1"
        assert event.location == "San Francisco, United States"
        assert event.session_id == "sess-okta-001"
        assert event.source_provider == "okta"

    def test_okta_logs_processed_by_full_pipeline(self):
        """
        Verify Okta events pass through the identical journey reconstructor
        and detection engine facade without requiring any code changes to the core.
        """
        okta_events = generate_okta_fixtures()
        result = self.pipeline.process_raw_events(okta_events, provider="okta")

        assert result.provider == "okta"
        assert len(result.normalized_events) == 2
        assert len(result.journeys) == 1

        journey = result.journeys[0]
        assert journey.user_id == "alex@company.com"
        assert len(journey.events) == 2
        # Chronological sequence: FIDO2 failure followed by password success
        assert journey.events[0].authentication_method == "passkey"
        assert journey.events[0].outcome == "FAILURE"
        assert journey.events[1].authentication_method == "password"
        assert journey.events[1].outcome == "SUCCESS"

        # Engine detection check
        alert = result.alerts[0]
        assert alert.drift_detected is True
        assert alert.drift_result.previous_method == "passkey"
        assert alert.drift_result.current_method == "password"

