"""
AuthDrift: Contextual Correlation Engine.
Correlates authentication drift with device changes, location changes,
authenticator registrations, and failure sequences.
"""

from typing import List, Optional, Set
from backend.models.event import AuthenticationEvent
from backend.models.detection import ContextEvidence


class ContextAnalyzer:
    """
    Analyzes contextual signals from raw event data.
    Strictly avoids fabricating information: missing fields remain None.
    Enforces user isolation to avoid cross-user contamination.
    """

    def analyze_journey_context(
        self,
        journey: List[AuthenticationEvent],
        known_devices: Optional[Set[str]] = None,
        known_locations: Optional[Set[str]] = None,
        known_authenticators: Optional[Set[str]] = None
    ) -> ContextEvidence:
        """
        Extracts and correlates contextual signals from an authentication journey.
        """
        if not journey:
            return ContextEvidence(evidence_notes=["Empty journey provided; no context available."])

        # Verify single user isolation
        user_ids = {e.user_id for e in journey}
        if len(user_ids) > 1:
            raise ValueError(
                f"Cross-user journey contamination detected: Multiple user_ids {user_ids} in single journey."
            )

        known_devs = set(known_devices) if known_devices else set()
        known_locs = set(known_locations) if known_locations else set()
        known_auths = set(known_authenticators) if known_authenticators else set()

        is_new_device: Optional[bool] = None
        detected_device: Optional[str] = None
        is_location_changed: Optional[bool] = None
        detected_location: Optional[str] = None
        authenticator_registered: Optional[bool] = None
        detected_authenticator: Optional[str] = None
        prior_failures_count: int = 0
        notes: List[str] = []

        for event in journey:
            # Track failure count
            if event.outcome.strip().upper() in ["FAILURE", "FAILED", "ERROR"]:
                prior_failures_count += 1

            # Analyze Device Signal
            if event.device_id is not None:
                detected_device = event.device_id
                if known_devs:
                    if event.device_id not in known_devs:
                        is_new_device = True
                        notes.append(f"Unrecognized device detected: '{event.device_id}'.")
                    else:
                        is_new_device = False
                else:
                    is_new_device = None

            # Analyze Location Signal
            if event.location is not None:
                detected_location = event.location
                if known_locs:
                    if event.location not in known_locs:
                        is_location_changed = True
                        notes.append(f"Unrecognized location observed: '{event.location}'.")
                    else:
                        is_location_changed = False
                else:
                    is_location_changed = None

            # Analyze Authenticator Registration Signal
            if event.authenticator_id is not None:
                detected_authenticator = event.authenticator_id
                if event.event_type.strip().upper() in ["REGISTER_AUTHENTICATOR", "UPDATE_CREDENTIAL", "CREDENTIAL_REGISTER"]:
                    authenticator_registered = True
                    notes.append(f"New authenticator registered during session: '{event.authenticator_id}'.")
                elif known_auths and event.authenticator_id not in known_auths:
                    authenticator_registered = True
                    notes.append(f"Unregistered authenticator used: '{event.authenticator_id}'.")

        if is_new_device is None and detected_device is None:
            notes.append("Device context unavailable in event logs.")

        if is_location_changed is None and detected_location is None:
            notes.append("Location context unavailable in event logs.")

        return ContextEvidence(
            is_new_device=is_new_device,
            device_id=detected_device,
            is_location_changed=is_location_changed,
            location=detected_location,
            authenticator_registered=authenticator_registered,
            authenticator_id=detected_authenticator,
            prior_failures_count=prior_failures_count,
            evidence_notes=notes
        )
