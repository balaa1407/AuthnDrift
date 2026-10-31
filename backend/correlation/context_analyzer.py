"""
AuthDrift: Contextual Correlation Engine.
Correlates authentication drift with per-user device baselines, location profiles,
explicit authenticator registrations, and failure sequences.
"""

from typing import Dict, List, Optional, Set
from backend.models.event import AuthenticationEvent
from backend.models.detection import ContextEvidence
from backend.correlation.location_profiler import LocationProfiler, LocationStatus, UserLocationProfile


REGISTRATION_EVENT_TYPES: Set[str] = {
    "REGISTER_AUTHENTICATOR",
    "UPDATE_CREDENTIAL",
    "CREDENTIAL_REGISTER",
    "REGISTER_CREDENTIAL",
    "USER.MFA.FACTOR.ACTIVATE",
    "FACTOR.ENROLL",
    "USER.CREDENTIAL.ENROLL",
}


class ContextAnalyzer:
    """
    Analyzes contextual signals from raw event data.
    Strictly avoids fabricating information: missing fields remain None or UNKNOWN.
    Enforces user isolation to avoid cross-user contamination.
    """

    def analyze_journey_context(
        self,
        journey: List[AuthenticationEvent],
        known_devices: Optional[Set[str]] = None,
        known_locations: Optional[Set[str]] = None,
        known_authenticators: Optional[Set[str]] = None,
        location_profiler: Optional[LocationProfiler] = None,
        user_profiles: Optional[Dict[str, UserLocationProfile]] = None
    ) -> ContextEvidence:
        """
        Extracts and correlates contextual signals from an authentication journey.
        """
        if not journey:
            return ContextEvidence(
                location_status=LocationStatus.UNKNOWN.value,
                evidence_notes=["Empty journey provided; no context available."]
            )

        # Verify single user isolation
        user_ids = {e.user_id for e in journey if e.user_id}
        if len(user_ids) > 1:
            raise ValueError(
                f"Cross-user journey contamination detected: Multiple user_ids {user_ids} in single journey."
            )
        current_user = list(user_ids)[0] if user_ids else "unknown_user"

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

        is_new_device: Optional[bool] = None
        detected_device: Optional[str] = None
        is_location_changed: Optional[bool] = None
        detected_location: Optional[str] = None
        primary_location: Optional[str] = None
        location_status: str = LocationStatus.UNKNOWN.value
        detected_ip: Optional[str] = None
        authenticator_registered: Optional[bool] = None
        detected_authenticator: Optional[str] = None
        prior_failures_count: int = 0
        notes: List[str] = []

        # Collect observations across journey
        observed_devices = [e.device_id for e in deduped_journey if e.device_id is not None]
        observed_locations = [e.location for e in deduped_journey if e.location is not None]
        observed_ips = [e.ip_address for e in deduped_journey if e.ip_address is not None]

        if observed_ips:
            detected_ip = observed_ips[-1]

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

        # 3. Location Analysis (Per-User Historical Baseline)
        if not observed_locations:
            is_location_changed = None
            detected_location = None
            primary_location = None
            location_status = LocationStatus.UNKNOWN.value
            notes.append("Location context unavailable in event logs.")
        else:
            # Sticky anomaly: pick first unrecognized location if any, else last observed
            loc_candidate = observed_locations[-1]

            # Priority A: Check LocationProfiler
            if location_profiler:
                # Test each observed location; if any is NEW, flag it
                has_new = False
                eval_primary = None
                for loc in observed_locations:
                    status, p_loc = location_profiler.evaluate_location(current_user, loc)
                    eval_primary = p_loc or eval_primary
                    if status == LocationStatus.NEW:
                        loc_candidate = loc
                        has_new = True
                        break

                status, p_loc = location_profiler.evaluate_location(current_user, loc_candidate)
                primary_location = eval_primary or p_loc
                location_status = LocationStatus.NEW.value if has_new else status.value
                detected_location = loc_candidate

                if location_status == LocationStatus.KNOWN.value:
                    is_location_changed = False
                    notes.append(f"Location '{detected_location}' matches established baseline (Primary: '{primary_location}').")
                elif location_status == LocationStatus.NEW.value:
                    is_location_changed = True
                    notes.append(f"New location '{detected_location}' observed; differs from established baseline (Primary: '{primary_location}').")
                else:
                    is_location_changed = None
                    notes.append(f"Location '{detected_location}' observed; insufficient baseline history for user '{current_user}' (status: UNKNOWN).")

            # Priority B: Check user_profiles dict
            elif user_profiles and current_user in user_profiles:
                u_prof = user_profiles[current_user]
                primary_location = u_prof.primary_location
                if not u_prof.is_baseline_established:
                    is_location_changed = None
                    detected_location = loc_candidate
                    location_status = LocationStatus.UNKNOWN.value
                    notes.append(f"Location '{detected_location}' observed; insufficient baseline history for user '{current_user}' (status: UNKNOWN).")
                else:
                    unrec_locs = [l for l in observed_locations if l not in u_prof.known_locations]
                    if unrec_locs:
                        is_location_changed = True
                        detected_location = unrec_locs[0]
                        location_status = LocationStatus.NEW.value
                        notes.append(f"New location '{detected_location}' observed; differs from established baseline (Primary: '{primary_location}').")
                    else:
                        is_location_changed = False
                        detected_location = loc_candidate
                        location_status = LocationStatus.KNOWN.value
                        notes.append(f"Location '{detected_location}' matches established baseline (Primary: '{primary_location}').")

            # Priority C: Legacy fallback to known_locations set
            elif known_locations:
                known_locs = set(known_locations)
                unrecognized_locs = [l for l in observed_locations if l not in known_locs]
                if unrecognized_locs:
                    is_location_changed = True
                    detected_location = unrecognized_locs[0]
                    location_status = LocationStatus.NEW.value
                    notes.append(f"Unrecognized location observed: '{detected_location}'.")
                else:
                    is_location_changed = False
                    detected_location = observed_locations[-1]
                    location_status = LocationStatus.KNOWN.value
            else:
                is_location_changed = None
                detected_location = observed_locations[-1]
                primary_location = None
                location_status = LocationStatus.UNKNOWN.value
                notes.append(f"Location '{detected_location}' observed; no baseline available for comparison.")

        # 4. Authenticator Registration vs. Authenticator Usage Analysis
        # Registration must ONLY be inferred from explicit registration event types,
        # never simply because an authenticator_id appears in a normal login event.
        for event in deduped_journey:
            if event.authenticator_id is not None:
                detected_authenticator = event.authenticator_id

            event_type_str = str(event.event_type or "").strip().upper()
            if event_type_str in REGISTRATION_EVENT_TYPES:
                authenticator_registered = True
                reg_auth = event.authenticator_id or detected_authenticator or "unspecified"
                notes.append(
                    f"Explicit authenticator registration observed: '{reg_auth}' "
                    f"via event '{event_type_str}'."
                )
                break

        return ContextEvidence(
            is_new_device=is_new_device,
            device_id=detected_device,
            is_location_changed=is_location_changed,
            location=detected_location,
            primary_location=primary_location,
            location_status=location_status,
            ip_address=detected_ip,
            authenticator_registered=authenticator_registered,
            authenticator_id=detected_authenticator,
            prior_failures_count=prior_failures_count,
            evidence_notes=notes
        )
