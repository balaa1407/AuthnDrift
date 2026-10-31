"""
AuthDrift: Keycloak Event Normalizer.
Converts raw Keycloak user event logs (from REST API or JBoss Event Listener)
into the normalized AuthenticationEvent schema with orthogonal event classification.
"""

from typing import Any, Dict, Optional
import uuid
from backend.models.event import AuthenticationEvent, EventCategory
from backend.normalization.base import BaseEventNormalizer
from backend.assurance.assurance_assignment import assign_event_assurance


class KeycloakEventNormalizer(BaseEventNormalizer):
    """
    Normalizes Keycloak user authentication and registration events.
    Handles standard Keycloak 20+ event schemas with graceful fallbacks.
    Separates IP address from geographic location strictly without fabrication.
    Enforces orthogonal event classification between authentication ceremonies,
    session lifecycle events, and account factor mutations.
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
        "refresh_token": "refresh_token",
    }

    AUTHENTICATION_EVENT_TYPES = {
        "LOGIN",
        "LOGIN_ERROR",
    }

    SESSION_LIFECYCLE_EVENT_TYPES = {
        "REFRESH_TOKEN",
        "REFRESH_TOKEN_ERROR",
        "CODE_TO_TOKEN",
        "CODE_TO_TOKEN_ERROR",
        "LOGOUT",
        "SESSION_LOGOUT",
    }

    ACCOUNT_LIFECYCLE_EVENT_TYPES = {
        "REGISTER",
        "REGISTER_ERROR",
        "REGISTER_AUTHENTICATOR",
        "UPDATE_PASSWORD",
        "UPDATE_PASSWORD_ERROR",
        "UPDATE_TOTP",
        "UPDATE_CREDENTIAL",
        "DELETE_CREDENTIAL",
        "CREDENTIAL_REGISTER",
        "FEDERATED_IDENTITY_LINK",
        "FEDERATED_IDENTITY_LINK_ERROR",
    }

    SUCCESS_EVENT_TYPES = {
        "LOGIN",
        "REGISTER",
        "REFRESH_TOKEN",
        "CODE_TO_TOKEN",
        "UPDATE_PASSWORD",
        "FEDERATED_IDENTITY_LINK",
        "REGISTER_AUTHENTICATOR",
    }

    FAILURE_EVENT_TYPES = {
        "LOGIN_ERROR",
        "REGISTER_ERROR",
        "REFRESH_TOKEN_ERROR",
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

        # 4. Event Type & Orthogonal Event Category Classification
        event_type = str(raw.get("type") or raw.get("eventType") or "LOGIN").strip().upper()

        if event_type in self.SESSION_LIFECYCLE_EVENT_TYPES or "REFRESH" in event_type or "LOGOUT" in event_type:
            event_category = EventCategory.SESSION_LIFECYCLE.value
        elif event_type in self.ACCOUNT_LIFECYCLE_EVENT_TYPES or "REGISTER" in event_type or "UPDATE" in event_type or "CREDENTIAL" in event_type:
            event_category = EventCategory.ACCOUNT_LIFECYCLE.value
        elif event_type in self.AUTHENTICATION_EVENT_TYPES or event_type.startswith("LOGIN"):
            event_category = EventCategory.AUTHENTICATION.value
        else:
            # Conservative default
            event_category = EventCategory.AUTHENTICATION.value

        # 5. Outcome determination
        explicit_outcome = raw.get("outcome") or details.get("outcome")
        if explicit_outcome:
            outcome = "SUCCESS" if str(explicit_outcome).strip().upper() in ["SUCCESS", "ALLOW"] else "FAILURE"
        elif event_type in self.FAILURE_EVENT_TYPES or event_type.endswith("_ERROR"):
            outcome = "FAILURE"
        elif event_type in self.SUCCESS_EVENT_TYPES:
            outcome = "SUCCESS"
        else:
            # Check for error field in details or raw
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
            if "webauthn" in str(event_type).lower():
                auth_method = "passkey"
            elif event_type == "REGISTER_AUTHENTICATOR":
                auth_method = "webauthn"
            elif event_category == EventCategory.SESSION_LIFECYCLE.value:
                auth_method = "refresh_token"
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

        event = AuthenticationEvent(
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
            source_provider="keycloak",
            event_category=event_category
        )

        # Annotate domain-restricted assurance levels
        assign_event_assurance(event)
        return event
