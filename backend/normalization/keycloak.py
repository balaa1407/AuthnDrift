"""
AuthDrift: Keycloak Event Normalizer.
Converts raw Keycloak user event logs (from REST API or JBoss Event Listener)
into the normalized AuthenticationEvent schema.
"""

from typing import Any, Dict, Optional
import uuid
from backend.models.event import AuthenticationEvent
from backend.normalization.base import BaseEventNormalizer


class KeycloakEventNormalizer(BaseEventNormalizer):
    """
    Normalizes Keycloak user authentication and registration events.
    Handles standard Keycloak 20+ event schemas with graceful fallbacks.
    Separates IP address from geographic location strictly without fabrication.
    """

    METHOD_MAPPING = {
        # High Assurance / FIDO2
        "webauthn": "passkey",
        "webauthn-passwordless": "passkey",
        "passkey": "passkey",
        "fido2": "passkey",
        "hardware_token": "hardware_token",
        "client_cert": "client_cert",

        # Medium Assurance
        "totp": "totp",
        "otp": "otp",
        "sms_otp": "sms_otp",
        "sms": "sms",
        "email_otp": "email_otp",
        "push_notification": "push_notification",

        # Low Assurance
        "password": "password",
        "pin": "pin",
        "secret": "password",
        "knowledge_based": "knowledge_based",
    }

    SUCCESS_EVENT_TYPES = {
        "LOGIN",
        "REGISTER",
        "CODE_TO_TOKEN",
        "UPDATE_PASSWORD",
        "FEDERATED_IDENTITY_LINK",
        "REGISTER_AUTHENTICATOR",
    }

    FAILURE_EVENT_TYPES = {
        "LOGIN_ERROR",
        "REGISTER_ERROR",
        "CODE_TO_TOKEN_ERROR",
        "UPDATE_PASSWORD_ERROR",
        "FEDERATED_IDENTITY_LINK_ERROR",
    }

    def normalize_single(self, raw: Dict[str, Any]) -> Optional[AuthenticationEvent]:
        """
        Transforms a Keycloak event JSON object into an AuthenticationEvent.
        """
        if not isinstance(raw, dict):
            return None

        # 1. Event Identifier
        event_id = str(raw.get("id") or raw.get("eventId") or f"kc-{uuid.uuid4()}")
        self._store_raw(event_id, raw)

        # 2. Timestamp
        raw_time = raw.get("time") or raw.get("timestamp")
        timestamp = self._parse_timestamp(raw_time)

        # 3. User Identifier (prioritize human-readable username from details, fallback to userId)
        details = raw.get("details") if isinstance(raw.get("details"), dict) else {}
        user_id = str(
            details.get("username")
            or raw.get("userId")
            or raw.get("user_id")
            or raw.get("username")
            or "unknown_user"
        ).strip()

        # 4. Event Type
        event_type = str(raw.get("type") or raw.get("eventType") or "LOGIN").strip().upper()

        # 5. Outcome determination
        explicit_outcome = raw.get("outcome") or details.get("outcome")
        if explicit_outcome:
            outcome = "SUCCESS" if str(explicit_outcome).strip().upper() in ["SUCCESS", "ALLOW"] else "FAILURE"
        elif event_type in self.SUCCESS_EVENT_TYPES:
            outcome = "SUCCESS"
        elif event_type in self.FAILURE_EVENT_TYPES:
            outcome = "FAILURE"
        else:
            # Check for error field in details
            outcome = "FAILURE" if ("error" in details or "error" in raw) else "SUCCESS"

        # 6. Authentication Method extraction
        auth_method_raw = (
            details.get("auth_method")
            or details.get("credential_type")
            or details.get("custom_method")
            or details.get("identity_provider")
            or raw.get("auth_method")
            or raw.get("authentication_method")
        )

        if auth_method_raw:
            method_clean = str(auth_method_raw).strip().lower()
            auth_method = self.METHOD_MAPPING.get(method_clean, method_clean)
        else:
            # If method is missing:
            # If registration of webauthn/passkey
            if "webauthn" in str(event_type).lower():
                auth_method = "passkey"
            elif event_type == "REGISTER_AUTHENTICATOR":
                auth_method = "webauthn"
            else:
                # Keycloak default primary credential is password when not specified
                auth_method = "password"

        # 7. Contextual Fields (preserved cleanly as None if absent, no fabrication)
        device_id = (
            details.get("device_id")
            or details.get("device_name")
            or raw.get("device_id")
        )
        if device_id:
            device_id = str(device_id).strip()
        else:
            device_id = None

        # Extract IP address separately
        raw_ip = (
            raw.get("ipAddress")
            or details.get("ip_address")
            or details.get("ipAddress")
            or raw.get("ip_address")
        )
        if raw_ip:
            ip_address = str(raw_ip).strip()
        else:
            ip_address = None

        # Extract geographic location strictly - NEVER fall back to IP address
        location = self._compose_location(
            city=details.get("city") or raw.get("city"),
            country=details.get("country") or raw.get("country"),
            fallback=(
                details.get("location")
                or details.get("geo_location")
                or details.get("geographic_location")
                or raw.get("location")
            )
        )

        authenticator_id = (
            details.get("authenticator_id")
            or details.get("credential_id")
            or raw.get("authenticator_id")
        )
        if authenticator_id:
            authenticator_id = str(authenticator_id).strip()
        else:
            authenticator_id = None

        session_id = (
            raw.get("sessionId")
            or raw.get("session_id")
            or details.get("session_id")
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
            ip_address=ip_address,
            authenticator_id=authenticator_id,
            session_id=session_id,
            source_provider="keycloak"
        )
