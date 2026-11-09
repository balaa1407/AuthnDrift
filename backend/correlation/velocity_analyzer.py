"""
AuthDrift: Geodesic Travel Velocity & Impossible Travel Anomaly Analyzer.

Computes great-circle distance (Haversine formula) and physical travel velocity
between sequential authentication events to detect physically impossible transit
(e.g., supersonic speeds > 900 km/h indicative of VPN hopping, credential theft, or proxying).
"""

import math
from datetime import datetime
from typing import Any, Dict, Optional, Tuple


# Known major city coordinates (latitude, longitude) for empirical enterprise testing
KNOWN_CITY_COORDINATES: Dict[str, Tuple[float, float]] = {
    "bengaluru": (12.9716, 77.5946),
    "bangalore": (12.9716, 77.5946),
    "frankfurt": (50.1109, 8.6821),
    "berlin": (52.5200, 13.4050),
    "london": (51.5074, -0.1278),
    "new york": (40.7128, -74.0060),
    "san francisco": (37.7749, -122.4194),
    "reykjavik": (64.1466, -21.9426),
    "bucharest": (44.4268, 26.1025),
    "moscow": (55.7558, 37.6173),
    "beijing": (39.9042, 116.4074),
    "singapore": (1.3521, 103.8198),
    "sydney": (-33.8688, 151.2093),
    "tokyo": (35.6762, 139.6503),
    "dubai": (25.2048, 55.2708),
    "mumbai": (19.0760, 72.8777),
    "delhi": (28.7041, 77.1025),
    "paris": (48.8566, 2.3522),
    "amsterdam": (52.3676, 4.9041),
    "zurich": (47.3769, 8.5417),
}

CITY_COORDINATES = KNOWN_CITY_COORDINATES

# Commercial aviation maximum cruising speed threshold (km/h)
MAX_PLAUSIBLE_AIR_TRAVEL_SPEED_KMH: float = 900.0
EARTH_RADIUS_KM: float = 6371.0


def haversine_distance_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """
    Computes great-circle Haversine distance between two sets of coordinates in kilometers.
    """
    return calculate_haversine_distance((lat1, lon1), (lat2, lon2))


def resolve_coordinates(location_str: Optional[str]) -> Optional[Tuple[float, float]]:
    """
    Resolves geographic coordinates from standard location strings.
    Matches city keywords case-insensitively.
    """
    if not location_str:
        return None
    loc_clean = location_str.lower().strip()
    for city, coords in KNOWN_CITY_COORDINATES.items():
        if city in loc_clean:
            return coords
    return None


def calculate_haversine_distance(coord1: Tuple[float, float], coord2: Tuple[float, float]) -> float:
    """
    Calculates great-circle distance between two latitude/longitude points in kilometers.
    """
    lat1, lon1 = coord1
    lat2, lon2 = coord2

    phi1 = math.radians(lat1)
    phi2 = math.radians(lat2)
    delta_phi = math.radians(lat2 - lat1)
    delta_lambda = math.radians(lon2 - lon1)

    a = (
        math.sin(delta_phi / 2.0) ** 2
        + math.cos(phi1) * math.cos(phi2) * math.sin(delta_lambda / 2.0) ** 2
    )
    c = 2.0 * math.atan2(math.sqrt(a), math.sqrt(1.0 - a))
    return EARTH_RADIUS_KM * c


def evaluate_travel_velocity(
    source_location: Optional[str],
    target_location: Optional[str],
    source_time: Optional[datetime],
    target_time: Optional[datetime]
) -> Optional[Dict[str, Any]]:
    """
    Evaluates travel velocity between sequential events.
    Returns a dictionary with distance, time delta, velocity, and an impossible_travel flag.
    Returns None if locations or timestamps are missing or identical.
    """
    if not source_location or not target_location or not source_time or not target_time:
        return None

    if source_location.strip().lower() == target_location.strip().lower():
        return None

    coords1 = resolve_coordinates(source_location)
    coords2 = resolve_coordinates(target_location)

    if not coords1 or not coords2:
        return None

    distance_km = calculate_haversine_distance(coords1, coords2)
    time_delta_seconds = abs((target_time - source_time).total_seconds())

    # Avoid division by zero
    if time_delta_seconds < 1.0:
        time_delta_seconds = 1.0

    time_delta_hours = time_delta_seconds / 3600.0
    velocity_kmh = distance_km / time_delta_hours

    # An impossible travel anomaly requires non-trivial distance (>50km) and supersonic velocity
    is_impossible = (
        distance_km > 50.0
        and velocity_kmh > MAX_PLAUSIBLE_AIR_TRAVEL_SPEED_KMH
    )

    return {
        "source_location": source_location,
        "target_location": target_location,
        "distance_km": round(distance_km, 1),
        "time_delta_seconds": round(time_delta_seconds, 1),
        "velocity_kmh": round(velocity_kmh, 1),
        "is_impossible_travel": is_impossible,
        "speed_of_sound_ratio": round(velocity_kmh / 1234.8, 2)
    }
