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
        user_ids = {e.user_id for e in journey if e.user_id}
        if len(user_ids) > 1:
            raise ValueError(
                f"Cross-user journey contamination detected: Multiple user_ids {user_ids} in single journey."
            )

        # Deduplicate events by event_id to prevent log-replay artifacting
        deduped_journey: List[AuthenticationEvent] = []
        seen_ids: Set[str] = set()
        for event in journey:
            if event.event_id and event.event_id in seen_ids:
                continue
            if event.event_id:
                seen_ids.add(event.event_id)
            deduped_journey.append(event)

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

        # Collect observations across journey
        observed_devices = [e.device_id for e in deduped_journey if e.device_id is not None]
        observed_locations = [e.location for e in deduped_journey if e.location is not None]

        # 1. Failure Counting
        for event in deduped_journey:
            if event.outcome and str(event.outcome).strip().upper() in ["FAILURE", "FAILED", "ERROR"]:
                prior_failures_count += 1

        # 2. Device Analysis (Persistent/Sticky Anomaly Handling)
        if not observed_devices:
            is_new_device = None
            detected_device = None
            notes.append("Device context unavailable in event logs.")
        elif not known_devs:
            # Device is present, but baseline profile is unconfigured
            is_new_device = None
            detected_device = observed_devices[-1]
            notes.append(f"Device '{detected_device}' observed; no baseline available for comparison.")
        else:
            unrecognized_devs = [d for d in observed_devices if d not in known_devs]
            if unrecognized_devs:
                is_new_device = True
                detected_device = unrecognized_devs[0]
                notes.append(f"Unrecognized device detected: '{detected_device}'.")
            else:
                is_new_device = False
                detected_device = observed_devices[-1]

        # 3. Location Analysis (Persistent/Sticky Anomaly Handling)
        if not observed_locations:
            is_location_changed = None
            detected_location = None
            notes.append("Location context unavailable in event logs.")
        elif not known_locs:
            is_location_changed = None
            detected_location = observed_locations[-1]
            notes.append(f"Location '{detected_location}' observed; no baseline available for comparison.")
        else:
            unrecognized_locs = [l for l in observed_locations if l not in known_locs]
            if unrecognized_locs:
                is_location_changed = True
                detected_location = unrecognized_locs[0]
                notes.append(f"Unrecognized location observed: '{detected_location}'.")
            else:
                is_location_changed = False
                detected_location = observed_locations[-1]

        # 4. Authenticator Registration Analysis
        for event in deduped_journey:
            if event.authenticator_id is not None or str(event.event_type or "").strip().upper() in [
                "REGISTER_AUTHENTICATOR", "UPDATE_CREDENTIAL", "CREDENTIAL_REGISTER", "REGISTER_CREDENTIAL"
            ]:
                detected_authenticator = event.authenticator_id
                event_type_str = str(event.event_type).strip().upper() if event.event_type else ""
                if event_type_str in ["REGISTER_AUTHENTICATOR", "UPDATE_CREDENTIAL", "CREDENTIAL_REGISTER", "REGISTER_CREDENTIAL"]:
                    authenticator_registered = True
                    notes.append(f"New authenticator registered during session: '{event.authenticator_id or 'unspecified'}'.")
                    break
                elif known_auths and event.authenticator_id and event.authenticator_id not in known_auths:
                    authenticator_registered = True
                    notes.append(f"Unregistered authenticator used: '{event.authenticator_id}'.")
                    break

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
