"""
AuthDrift: Per-User Historical Location Profiler.
Replaces global static location whitelists with dynamic per-user baselines
derived deterministically from historical successful authentications.
"""

from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple
from backend.models.event import AuthenticationEvent


class LocationStatus(str, Enum):
    """
    Explicit status of an observed location relative to a user's established baseline.
    """
    KNOWN = "KNOWN"
    NEW = "NEW"
    UNKNOWN = "UNKNOWN"


@dataclass
class UserLocationProfile:
    """
    Historical location baseline profile for an individual user.
    """
    user_id: str
    primary_location: Optional[str] = None
    known_locations: Set[str] = field(default_factory=set)
    successful_observations_count: int = 0
    is_baseline_established: bool = False
    last_updated: Optional[datetime] = None


class LocationProfiler:
    """
    Establishes and evaluates per-user location baselines.

    Rules:
    1. Baselines are established ONLY from successful authentications (outcome == SUCCESS).
    2. A minimum number of successful observations (min_successful_observations) is required.
    3. Primary location is determined deterministically by frequency (mode).
    4. If history or location is insufficient, status is UNKNOWN (never falsely flags NEW).
    """

    def __init__(
        self,
        min_successful_observations: int = 2,
        lookback_limit: Optional[int] = None
    ):
        self.min_successful_observations = max(1, min_successful_observations)
        self.lookback_limit = lookback_limit
        self._profiles: Dict[str, UserLocationProfile] = {}

    def build_profiles(self, events: List[AuthenticationEvent]) -> Dict[str, UserLocationProfile]:
        """
        Builds or rebuilds user location profiles from a collection of historical events.
        Filters strictly for successful authentications with valid location data.

        Any previously built profiles are discarded first so that stale baselines
        from an earlier ingestion can never leak into this one.
        """
        self._profiles = {}
        user_successful_locations: Dict[str, List[Tuple[datetime, str]]] = {}

        for event in events:
            if not event.user_id:
                continue

            # Only consider successful authentications
            outcome_str = str(event.outcome or "").strip().upper()
            if outcome_str not in ["SUCCESS", "ALLOW"]:
                continue

            # Location must be present and non-empty
            loc = str(event.location or "").strip()
            if not loc:
                continue

            ts = event.timestamp if event.timestamp else datetime.min
            if event.user_id not in user_successful_locations:
                user_successful_locations[event.user_id] = []
            user_successful_locations[event.user_id].append((ts, loc))

        for user_id, obs_list in user_successful_locations.items():
            # Sort chronologically
            obs_list.sort(key=lambda x: x[0])

            # Apply lookback window if configured
            if self.lookback_limit and len(obs_list) > self.lookback_limit:
                obs_list = obs_list[-self.lookback_limit:]

            obs_count = len(obs_list)
            locations_observed = [loc for _, loc in obs_list]

            if obs_count >= self.min_successful_observations:
                # Deterministic primary location: highest frequency, tie-break by most recent then alphabetical
                counts = Counter(locations_observed)
                # Sort keys by count desc, then most recent occurrence index desc, then alphabetical
                most_recent_idx = {loc: i for i, loc in enumerate(locations_observed)}
                sorted_locs = sorted(
                    counts.keys(),
                    key=lambda loc: (-counts[loc], -most_recent_idx[loc], loc)
                )
                primary = sorted_locs[0]
                known = set(counts.keys())

                profile = UserLocationProfile(
                    user_id=user_id,
                    primary_location=primary,
                    known_locations=known,
                    successful_observations_count=obs_count,
                    is_baseline_established=True,
                    last_updated=obs_list[-1][0] if obs_list else None
                )
            else:
                profile = UserLocationProfile(
                    user_id=user_id,
                    primary_location=None,
                    known_locations=set(locations_observed),
                    successful_observations_count=obs_count,
                    is_baseline_established=False,
                    last_updated=obs_list[-1][0] if obs_list else None
                )

            self._profiles[user_id] = profile

        return self._profiles

    def snapshot_before(
        self,
        events: List[AuthenticationEvent],
        user_id: str,
        before: datetime,
        exclude_event_ids: Optional[Set[str]] = None
    ) -> "LocationProfiler":
        """
        Returns a NEW profiler (same configuration) whose baseline for `user_id` is built
        only from that user's events strictly earlier than `before`.

        This guarantees that the journey being evaluated, and anything after it, cannot
        contaminate its own historical baseline, and that other users' events are ignored.
        """
        excluded = exclude_event_ids or set()
        history = [
            e for e in events
            if e.user_id == user_id
            and e.timestamp is not None
            and e.timestamp < before
            and e.event_id not in excluded
        ]
        snapshot = LocationProfiler(
            min_successful_observations=self.min_successful_observations,
            lookback_limit=self.lookback_limit
        )
        snapshot.build_profiles(history)
        return snapshot

    def get_profile(self, user_id: str) -> Optional[UserLocationProfile]:
        """Retrieves profile for a user, or None if not tracked."""
        return self._profiles.get(user_id)

    def set_profile(self, profile: UserLocationProfile) -> None:
        """Explicitly sets or overrides a profile."""
        self._profiles[profile.user_id] = profile

    def evaluate_location(
        self,
        user_id: str,
        observed_location: Optional[str]
    ) -> Tuple[LocationStatus, Optional[str]]:
        """
        Evaluates an observed location against a user's established historical baseline.
        Returns: (LocationStatus, primary_baseline_location)
        """
        clean_loc = str(observed_location or "").strip()
        if not clean_loc:
            return LocationStatus.UNKNOWN, None

        profile = self._profiles.get(user_id)
        if not profile or not profile.is_baseline_established or not profile.primary_location:
            return LocationStatus.UNKNOWN, None

        if clean_loc in profile.known_locations or clean_loc == profile.primary_location:
            return LocationStatus.KNOWN, profile.primary_location

        return LocationStatus.NEW, profile.primary_location

