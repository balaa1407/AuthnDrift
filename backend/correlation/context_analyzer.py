"""
AuthDrift: Contextual Correlation Engine.
Correlates authentication drift with per-user device baselines, location profiles,
explicit authenticator registrations, sequential telemetry deltas, and failure sequences.
"""

import ipaddress
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set
from backend.models.event import AuthenticationEvent
from backend.models.detection import ContextAnomaly, ContextEvidence
from backend.correlation.location_profiler import LocationProfiler, LocationStatus, UserLocationProfile
from backend.correlation.velocity_analyzer import evaluate_travel_velocity


REGISTRATION_EVENT_TYPES: Set[str] = {
    "REGISTER_AUTHENTICATOR",
    "UPDATE_CREDENTIAL",
    "CREDENTIAL_REGISTER",
    "REGISTER_CREDENTIAL",
    "USER.MFA.FACTOR.ACTIVATE",
    "FACTOR.ENROLL",
    "USER.CREDENTIAL.ENROLL",
}


def _utc_sort_key(ts: Optional[datetime]) -> datetime:
    """Normalizes timestamps to UTC-aware datetimes so naive and aware timestamps sort safely."""
    if ts is None:
        return datetime.min.replace(tzinfo=timezone.utc)
    if ts.tzinfo is None:
        return ts.replace(tzinfo=timezone.utc)
    return ts.astimezone(timezone.utc)


def _is_valid_ip(ip_str: Optional[str]) -> bool:
    """Returns True iff ip_str parses cleanly as an IPv4 or IPv6 address."""
    if not ip_str or not isinstance(ip_str, str):
        return False
    cleaned = ip_str.strip().strip("[]")
    if not cleaned:
        return False
    try:
        ipaddress.ip_address(cleaned)
        return True
    except ValueError:
        return False


def _is_same_subnet(ip_a: str, ip_b: str) -> Optional[bool]:
    """
    Returns True if ip_a and ip_b belong to the same /24 (IPv4) or /64 (IPv6) subnet,
    False if disparate subnets, or None if either address is invalid.
    """
    if not _is_valid_ip(ip_a) or not _is_valid_ip(ip_b):
        return None
    try:
        addr_a = ipaddress.ip_address(ip_a.strip().strip("[]"))
        addr_b = ipaddress.ip_address(ip_b.strip().strip("[]"))
        if addr_a.version != addr_b.version:
            return False
        prefix = 24 if addr_a.version == 4 else 64
        net_a = ipaddress.ip_network(f"{addr_a}/{prefix}", strict=False)
        return addr_b in net_a
    except ValueError:
        return None


def _ip_matches_baseline(ip_addr: str, baseline_ips: Set[str]) -> Optional[bool]:
    """
    Evaluates whether valid ip_addr matches any valid baseline IP directly or within the same /24 (IPv4) / /64 (IPv6) subnet.
    Returns None if ip_addr is invalid or baseline_ips contains no valid IP addresses.
    """
    if not _is_valid_ip(ip_addr):
        return None
    valid_candidates = [cand for cand in baseline_ips if _is_valid_ip(cand)]
    if not valid_candidates:
        return None
    target_addr = ipaddress.ip_address(ip_addr.strip().strip("[]"))
    for cand in valid_candidates:
        cand_addr = ipaddress.ip_address(cand.strip().strip("[]"))
        if target_addr == cand_addr or _is_same_subnet(str(cand_addr), str(target_addr)) is True:
            return True
    return False


class ContextAnalyzer:
    """
    Analyzes contextual signals and telemetry deltas across the full event sequence.
    Strictly avoids fabricating information: missing or invalid fields remain None or UNKNOWN.
    Enforces user isolation to avoid cross-user contamination.
    Emits discrete ContextAnomaly records for geographic, IP, and device deviations.
    """

    def analyze_journey_context(
        self,
        journey: List[AuthenticationEvent],
        known_devices: Optional[Set[str]] = None,
        known_locations: Optional[Set[str]] = None,
        known_authenticators: Optional[Set[str]] = None,
        known_ips: Optional[Set[str]] = None,
        primary_device: Optional[str] = None,
        primary_ip: Optional[str] = None,
        location_profiler: Optional[LocationProfiler] = None,
        user_profiles: Optional[Dict[str, UserLocationProfile]] = None,
        user_baselines: Optional[Dict[str, Dict[str, Any]]] = None,
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

        # Sort chronologically by timestamp
        sorted_journey = sorted(
            journey,
            key=lambda e: _utc_sort_key(e.timestamp)
        )

        # Deduplicate events by event_id to prevent log-replay artifacting
        deduped_journey: List[AuthenticationEvent] = []
        seen_ids: Set[str] = set()
        for event in sorted_journey:
            if event.event_id and event.event_id in seen_ids:
                continue
            if event.event_id:
                seen_ids.add(event.event_id)
            deduped_journey.append(event)

        # Per-user baseline isolation: if user_baselines dict is configured, use ONLY current_user's baselines
        known_devs = set(known_devices) if known_devices else set()
        resolved_known_ips = set(known_ips) if known_ips else set()

        if user_baselines and current_user in user_baselines:
            u_base = user_baselines[current_user] or {}
            if "known_devices" in u_base and u_base["known_devices"] is not None:
                known_devs = set(u_base["known_devices"])
            if u_base.get("primary_device"):
                primary_device = u_base["primary_device"]
                known_devs.add(primary_device)
            if "known_ips" in u_base and u_base["known_ips"] is not None:
                resolved_known_ips = set(u_base["known_ips"])
            if u_base.get("primary_ip"):
                primary_ip = u_base["primary_ip"]
                resolved_known_ips.add(primary_ip)

        if not primary_device and len(known_devs) == 1:
            primary_device = list(known_devs)[0]
        if not primary_ip and len(resolved_known_ips) == 1:
            primary_ip = list(resolved_known_ips)[0]

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
        context_anomalies: List[ContextAnomaly] = []

        # 1. Sequential Telemetry Delta Analysis across ALL events (including SESSION_LIFECYCLE and FAILURE)
        last_loc_event: Optional[AuthenticationEvent] = None
        last_ip_event: Optional[AuthenticationEvent] = None
        last_dev_event: Optional[AuthenticationEvent] = None

        for event in deduped_journey:
            stage = getattr(event, "event_category", "AUTHENTICATION")

            # Sequential location changes
            if event.location:
                if last_loc_event is not None and event.location != last_loc_event.location:
                    velocity_info = evaluate_travel_velocity(
                        source_location=last_loc_event.location,
                        target_location=event.location,
                        source_time=last_loc_event.timestamp,
                        target_time=event.timestamp
                    )
                    v_kmh = velocity_info.get("velocity_kmh") if velocity_info else None
                    is_imp = velocity_info.get("is_impossible_travel", False) if velocity_info else False
                    if is_imp and velocity_info:
                        notes.append(
                            f"Physically impossible travel velocity detected: {velocity_info['distance_km']} km traversed in "
                            f"{velocity_info['time_delta_seconds']}s ({velocity_info['velocity_kmh']} km/h)."
                        )

                    context_anomalies.append(ContextAnomaly(
                        source_event_id=last_loc_event.event_id,
                        target_event_id=event.event_id,
                        anomaly_type="LOCATION_CHANGE",
                        previous_value=last_loc_event.location,
                        current_value=event.location,
                        lifecycle_stage=stage,
                        velocity_kmh=v_kmh,
                        is_impossible_travel=is_imp
                    ))
                last_loc_event = event

            # Sequential IP changes
            if event.ip_address:
                if last_ip_event is not None and event.ip_address != last_ip_event.ip_address:
                    is_same_subnet = _is_same_subnet(last_ip_event.ip_address, event.ip_address)

                    if is_same_subnet:
                        notes.append(f"Sequential IP delta occurred within same /24 subnet: {last_ip_event.ip_address} ➔ {event.ip_address}.")
                    elif is_same_subnet is False:
                        notes.append(f"Sequential IP delta crossed distinct subnets: {last_ip_event.ip_address} ➔ {event.ip_address}.")

                    context_anomalies.append(ContextAnomaly(
                        source_event_id=last_ip_event.event_id,
                        target_event_id=event.event_id,
                        anomaly_type="IP_CHANGE",
                        previous_value=last_ip_event.ip_address,
                        current_value=event.ip_address,
                        lifecycle_stage=stage,
                        subnet_continuity=is_same_subnet
                    ))
                last_ip_event = event

            # Sequential device changes
            if event.device_id:
                if last_dev_event is not None and event.device_id != last_dev_event.device_id:
                    context_anomalies.append(ContextAnomaly(
                        source_event_id=last_dev_event.event_id,
                        target_event_id=event.event_id,
                        anomaly_type="DEVICE_CHANGE",
                        previous_value=last_dev_event.device_id,
                        current_value=event.device_id,
                        lifecycle_stage=stage
                    ))
                last_dev_event = event

        # Collect observations across journey
        observed_devices = [e.device_id for e in deduped_journey if e.device_id is not None]
        observed_locations = [e.location for e in deduped_journey if e.location is not None]
        observed_ips = [e.ip_address for e in deduped_journey if e.ip_address is not None]

        if observed_ips:
            detected_ip = observed_ips[-1]

        # 2. Failure Counting
        for event in deduped_journey:
            if event.outcome and str(event.outcome).strip().upper() in ["FAILURE", "FAILED", "ERROR"]:
                prior_failures_count += 1

        # 3. Device Analysis (Persistent/Sticky Anomaly Handling)
        dev_target_event_id = None
        if not observed_devices:
            is_new_device = None
            detected_device = None
            notes.append("Device context unavailable in event logs.")
        elif not known_devs:
            is_new_device = None
            detected_device = observed_devices[-1]
            notes.append(f"Device '{detected_device}' observed; no baseline available for comparison.")
        else:
            unrecognized_events = [e for e in deduped_journey if e.device_id and e.device_id not in known_devs]
            if unrecognized_events:
                is_new_device = True
                detected_device = unrecognized_events[0].device_id
                dev_target_event_id = unrecognized_events[0].event_id
                notes.append(f"Unrecognized device detected: '{detected_device}'.")
                # Ensure a DEVICE_CHANGE anomaly is recorded if not already recorded sequentially
                if not any(a.anomaly_type == "DEVICE_CHANGE" and a.current_value == detected_device for a in context_anomalies):
                    context_anomalies.append(ContextAnomaly(
                        source_event_id=None,
                        target_event_id=dev_target_event_id,
                        anomaly_type="DEVICE_CHANGE",
                        previous_value="BASELINE",
                        current_value=detected_device,
                        lifecycle_stage=getattr(unrecognized_events[0], "event_category", "AUTHENTICATION")
                    ))
            else:
                is_new_device = False
                detected_device = observed_devices[-1]

        # 4. Location Analysis (Per-User Historical Baseline)
        loc_target_event_id = None
        if not observed_locations:
            is_location_changed = None
            detected_location = None
            primary_location = None
            location_status = LocationStatus.UNKNOWN.value
            notes.append("Location context unavailable in event logs.")
        else:
            loc_candidate = observed_locations[-1]
            loc_target_event_id = deduped_journey[-1].event_id

            # Priority A: Check LocationProfiler
            if location_profiler:
                has_new = False
                eval_primary = None
                for ev in deduped_journey:
                    if ev.location:
                        status, p_loc = location_profiler.evaluate_location(current_user, ev.location)
                        eval_primary = p_loc or eval_primary
                        if status == LocationStatus.NEW:
                            loc_candidate = ev.location
                            loc_target_event_id = ev.event_id
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
                    if not any(a.anomaly_type == "LOCATION_CHANGE" and a.current_value == detected_location for a in context_anomalies):
                        context_anomalies.append(ContextAnomaly(
                            source_event_id=None,
                            target_event_id=loc_target_event_id,
                            anomaly_type="LOCATION_CHANGE",
                            previous_value=primary_location,
                            current_value=detected_location,
                            lifecycle_stage=getattr(deduped_journey[-1], "event_category", "AUTHENTICATION")
                        ))
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
                    unrec_events = [e for e in deduped_journey if e.location and e.location not in u_prof.known_locations]
                    if unrec_events:
                        is_location_changed = True
                        detected_location = unrec_events[0].location
                        loc_target_event_id = unrec_events[0].event_id
                        location_status = LocationStatus.NEW.value
                        notes.append(f"New location '{detected_location}' observed; differs from established baseline (Primary: '{primary_location}').")
                        if not any(a.anomaly_type == "LOCATION_CHANGE" and a.current_value == detected_location for a in context_anomalies):
                            context_anomalies.append(ContextAnomaly(
                                source_event_id=None,
                                target_event_id=loc_target_event_id,
                                anomaly_type="LOCATION_CHANGE",
                                previous_value=primary_location,
                                current_value=detected_location,
                                lifecycle_stage=getattr(unrec_events[0], "event_category", "AUTHENTICATION")
                            ))
                    else:
                        is_location_changed = False
                        detected_location = loc_candidate
                        location_status = LocationStatus.KNOWN.value
                        notes.append(f"Location '{detected_location}' matches established baseline (Primary: '{primary_location}').")

            # Priority C: Legacy fallback to known_locations set
            elif known_locations:
                known_locs = set(known_locations)
                unrec_events = [e for e in deduped_journey if e.location and e.location not in known_locs]
                if unrec_events:
                    is_location_changed = True
                    detected_location = unrec_events[0].location
                    loc_target_event_id = unrec_events[0].event_id
                    location_status = LocationStatus.NEW.value
                    notes.append(f"Unrecognized location observed: '{detected_location}'.")
                    if not any(a.anomaly_type == "LOCATION_CHANGE" and a.current_value == detected_location for a in context_anomalies):
                        context_anomalies.append(ContextAnomaly(
                            source_event_id=None,
                            target_event_id=loc_target_event_id,
                            anomaly_type="LOCATION_CHANGE",
                            previous_value="BASELINE",
                            current_value=detected_location,
                            lifecycle_stage=getattr(unrec_events[0], "event_category", "AUTHENTICATION")
                        ))
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

            # If sequential location change was detected, also reflect in is_location_changed
            if any(a.anomaly_type == "LOCATION_CHANGE" for a in context_anomalies):
                if is_location_changed is not False:
                    is_location_changed = True

        # 5. Authenticator Registration vs. Authenticator Usage Analysis
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

        # Client continuity evaluations (Person, Primary Device, Primary IP)
        is_primary_device_matched = None
        if detected_device and primary_device:
            is_primary_device_matched = (detected_device == primary_device)
        elif is_new_device is False:
            is_primary_device_matched = True
        elif is_new_device is True:
            is_primary_device_matched = False

        has_disparate_ip_change = any(
            a.anomaly_type == "IP_CHANGE" and not getattr(a, "subnet_continuity", False)
            for a in context_anomalies
        )
        baseline_ips = set(resolved_known_ips)
        if primary_ip:
            baseline_ips.add(primary_ip)

        is_primary_ip_matched = None
        if has_disparate_ip_change:
            is_primary_ip_matched = False
        elif detected_ip and not _is_valid_ip(detected_ip):
            is_primary_ip_matched = None
            notes.append(f"Invalid IP address format observed: '{detected_ip}'; baseline match left UNKNOWN.")
        elif detected_ip and baseline_ips:
            is_primary_ip_matched = _ip_matches_baseline(detected_ip, baseline_ips)

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
            primary_device=primary_device,
            primary_ip=primary_ip,
            is_primary_device_matched=is_primary_device_matched,
            is_primary_ip_matched=is_primary_ip_matched,
            evidence_notes=notes,
            context_anomalies=context_anomalies,
            vpn_proxy_status="NOT_VERIFIED",
        )
