"""
AuthDrift: Vendor-Neutral Provider Normalizer (Okta System Log).
Demonstrates that AuthDrift's normalization and downstream detection pipeline
is provider-agnostic and can ingest alternative enterprise identity logs.
"""

from typing import Any, Dict, Optional
import uuid
from backend.models.event import AuthenticationEvent
from backend.normalization.base import BaseEventNormalizer


class OktaEventNormalizer(BaseEventNormalizer):
    """
    Normalizes Okta System Log JSON events into AuthenticationEvent.
    Adheres strictly to the same common normalized schema.
    """

    METHOD_MAPPING = {
        "fido2 (webauthn)": "passkey",
        "fido2": "passkey",
        "webauthn": "passkey",
        "passkey": "passkey",
        "okta_verify": "totp",
        "google_authenticator": "totp",
        "totp": "totp",
        "sms": "sms",
        "phone_sms": "sms",
        "email": "email_otp",
        "password": "password",
        "push": "push_notification",
    }

    def normalize_single(self, raw: Dict[str, Any]) -> Optional[AuthenticationEvent]:
        """
        Transforms an Okta System Log record into a common AuthenticationEvent.
        """
        if not isinstance(raw, dict):
            return None

        # 1. Event ID
        event_id = str(raw.get("uuid") or raw.get("id") or f"okta-{uuid.uuid4()}")
        self._store_raw(event_id, raw)

        # 2. Timestamp
        raw_time = raw.get("published") or raw.get("timestamp") or raw.get("time")
        timestamp = self._parse_timestamp(raw_time)

        # 3. User Identifier (actor.alternateId or actor.id)
        actor = raw.get("actor") if isinstance(raw.get("actor"), dict) else {}
        user_id = str(
            actor.get("alternateId")
            or actor.get("id")
            or raw.get("userId")
            or "unknown_user"
        ).strip()

        # 4. Event Type
        event_type = str(raw.get("eventType") or "user.authentication.authenticate").strip()

        # 5. Outcome
        outcome_obj = raw.get("outcome") if isinstance(raw.get("outcome"), dict) else {}
        result_str = str(outcome_obj.get("result") or raw.get("outcome") or "SUCCESS").strip().upper()
        outcome = "SUCCESS" if result_str in ["SUCCESS", "ALLOW"] else "FAILURE"

        # 6. Authentication Method
        auth_context = raw.get("authenticationContext") if isinstance(raw.get("authenticationContext"), dict) else {}
        raw_method = (
            auth_context.get("credentialProvider")
            or auth_context.get("credentialType")
            or raw.get("auth_method")
            or raw.get("authentication_method")
        )

        if raw_method:
            method_clean = str(raw_method).strip().lower()
            auth_method = self.METHOD_MAPPING.get(method_clean, method_clean)
        else:
            if "mfa" in event_type.lower():
                auth_method = "totp"
            elif "factor.activate" in event_type.lower():
                auth_method = "webauthn"
            else:
                auth_method = "password"

        # 7. Contextual Signals
        client = raw.get("client") if isinstance(raw.get("client"), dict) else {}
        device_id = client.get("device") or client.get("id") or raw.get("device_id")
        if device_id:
            device_id = str(device_id).strip()
        else:
            device_id = None

        geo = client.get("geographicalContext") if isinstance(client.get("geographicalContext"), dict) else {}
        city = geo.get("city")
        country = geo.get("country")
        if city and country:
            location = f"{city}, {country}"
        elif city:
            location = str(city)
        elif raw.get("ipAddress"):
            location = str(raw.get("ipAddress"))
        else:
            location = None

        debug_context = raw.get("debugContext") if isinstance(raw.get("debugContext"), dict) else {}
        debug_data = debug_context.get("debugData") if isinstance(debug_context.get("debugData"), dict) else {}
        authenticator_id = (
            debug_data.get("factorId")
            or auth_context.get("authenticatorId")
            or raw.get("authenticator_id")
        )
        if authenticator_id:
            authenticator_id = str(authenticator_id).strip()
        else:
            authenticator_id = None

        session_id = (
            auth_context.get("externalSessionId")
            or raw.get("sessionId")
            or raw.get("session_id")
        )
        if session_id:
            session_id = str(session_id).strip()
        else:
            session_id = None

        return AuthenticationEvent(
            event_id=event_id,
            user_id=user_id,
            timestamp=timestamp,
            event_type=event_type,
            authentication_method=auth_method,
            outcome=outcome,
            device_id=device_id,
            location=location,
            authenticator_id=authenticator_id,
            session_id=session_id,
            source_provider="okta"
        )

