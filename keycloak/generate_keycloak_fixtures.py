"""
AuthDrift: Keycloak Fixture & Controlled Scenario Generator.
Generates realistic, reproducible Keycloak raw event logs representing TC01-TC10
and exports them to sample-data/ for offline testing and pipeline demonstration.
"""

import json
import os
import time
from typing import Any, Dict, List


def generate_keycloak_fixtures() -> List[Dict[str, Any]]:
    """
    Generates a suite of raw Keycloak events covering all controlled test scenarios:
    - TC01: Known device passkey success (Alice)
    - TC02: Failed passkey followed by password fallback (Bob)
    - TC03: Failed passkey, password success from new device (Carol)
    - TC04: Repeated failed password attempts (Dave)
    - TC05: Downgrade followed by authenticator registration (Eve)
    - TC06: Legitimate recovery / device migration (Frank)
    - TC07: Unknown authentication method (Grace)
    - TC08: Missing device and location context (Heidi)
    - TC09: Normal medium-assurance TOTP journey (Ivan)
    """
    # Fixed base timestamp in epoch milliseconds: 2026-10-30T14:00:00Z
    base_ms = 1793368800000

    events = [
        # --- TC01: Alice - Passkey Success on Known Device ---
        {
            "id": "kc-evt-alice-01",
            "time": base_ms,
            "type": "LOGIN",
            "realmId": "authdrift",
            "clientId": "authdrift-app",
            "userId": "usr-uuid-alice",
            "sessionId": "sess-alice-001",
            "ipAddress": "192.168.1.10",
            "details": {
                "username": "alice",
                "auth_method": "passkey",
                "device_id": "corporate-macbook-01",
                "location": "Bangalore, IN",
                "authenticator_id": "key-01"
            }
        },

        # --- TC02: Bob - Passkey Failure -> Password Fallback ---
        {
            "id": "kc-evt-bob-01",
            "time": base_ms + 10000,
            "type": "LOGIN_ERROR",
            "realmId": "authdrift",
            "clientId": "authdrift-app",
            "userId": "usr-uuid-bob",
            "sessionId": "sess-bob-001",
            "ipAddress": "192.168.1.20",
            "details": {
                "username": "bob",
                "auth_method": "passkey",
                "error": "webauthn_error_cancelled",
                "device_id": "laptop-01",
                "location": "Bangalore, IN"
            }
        },
        {
            "id": "kc-evt-bob-02",
            "time": base_ms + 25000,
            "type": "LOGIN",
            "realmId": "authdrift",
            "clientId": "authdrift-app",
            "userId": "usr-uuid-bob",
            "sessionId": "sess-bob-001",
            "ipAddress": "192.168.1.20",
            "details": {
                "username": "bob",
                "auth_method": "password",
                "device_id": "laptop-01",
                "location": "Bangalore, IN"
            }
        },

        # --- TC03: Carol - Passkey Failure -> Password Success on NEW Device ---
        {
            "id": "kc-evt-carol-01",
            "time": base_ms + 40000,
            "type": "LOGIN_ERROR",
            "realmId": "authdrift",
            "clientId": "authdrift-app",
            "userId": "usr-uuid-carol",
            "sessionId": "sess-carol-001",
            "ipAddress": "203.0.113.5",
            "details": {
                "username": "carol",
                "auth_method": "passkey",
                "error": "fido2_timeout",
                "device_id": "unfamiliar-phone-99",
                "location": "Berlin, Germany"
            }
        },
        {
            "id": "kc-evt-carol-02",
            "time": base_ms + 60000,
            "type": "LOGIN",
            "realmId": "authdrift",
            "clientId": "authdrift-app",
            "userId": "usr-uuid-carol",
            "sessionId": "sess-carol-001",
            "ipAddress": "203.0.113.5",
            "details": {
                "username": "carol",
                "auth_method": "password",
                "device_id": "unfamiliar-phone-99",
                "location": "Berlin, Germany"
            }
        },

        # --- TC04: Dave - Repeated Failed Authentication Attempts ---
        {
            "id": "kc-evt-dave-01",
            "time": base_ms + 70000,
            "type": "LOGIN_ERROR",
            "realmId": "authdrift",
            "clientId": "authdrift-app",
            "userId": "usr-uuid-dave",
            "sessionId": "sess-dave-001",
            "ipAddress": "198.51.100.22",
            "details": {
                "username": "dave",
                "auth_method": "password",
                "error": "invalid_user_credentials",
                "device_id": "unknown-box"
            }
        },
        {
            "id": "kc-evt-dave-02",
            "time": base_ms + 75000,
            "type": "LOGIN_ERROR",
            "realmId": "authdrift",
            "clientId": "authdrift-app",
            "userId": "usr-uuid-dave",
            "sessionId": "sess-dave-001",
            "ipAddress": "198.51.100.22",
            "details": {
                "username": "dave",
                "auth_method": "password",
                "error": "invalid_user_credentials",
                "device_id": "unknown-box"
            }
        },
        {
            "id": "kc-evt-dave-03",
            "time": base_ms + 80000,
            "type": "LOGIN_ERROR",
            "realmId": "authdrift",
            "clientId": "authdrift-app",
            "userId": "usr-uuid-dave",
            "sessionId": "sess-dave-001",
            "ipAddress": "198.51.100.22",
            "details": {
                "username": "dave",
                "auth_method": "password",
                "error": "invalid_user_credentials",
                "device_id": "unknown-box"
            }
        },

        # --- TC05: Eve - Downgrade followed by Authenticator Registration (Persistence) ---
        {
            "id": "kc-evt-eve-01",
            "time": base_ms + 90000,
            "type": "LOGIN_ERROR",
            "realmId": "authdrift",
            "clientId": "authdrift-app",
            "userId": "usr-uuid-eve",
            "sessionId": "sess-eve-001",
            "ipAddress": "192.168.1.30",
            "details": {
                "username": "eve",
                "auth_method": "passkey",
                "error": "device_not_registered"
            }
        },
        {
            "id": "kc-evt-eve-02",
            "time": base_ms + 105000,
            "type": "LOGIN",
            "realmId": "authdrift",
            "clientId": "authdrift-app",
            "userId": "usr-uuid-eve",
            "sessionId": "sess-eve-001",
            "ipAddress": "192.168.1.30",
            "details": {
                "username": "eve",
                "auth_method": "password"
            }
        },
        {
            "id": "kc-evt-eve-03",
            "time": base_ms + 120000,
            "type": "REGISTER_AUTHENTICATOR",
            "realmId": "authdrift",
            "clientId": "authdrift-app",
            "userId": "usr-uuid-eve",
            "sessionId": "sess-eve-001",
            "ipAddress": "192.168.1.30",
            "details": {
                "username": "eve",
                "auth_method": "webauthn",
                "authenticator_id": "rogue-token-007"
            }
        },

        # --- TC06: Frank - Legitimate Recovery / Migration ---
        {
            "id": "kc-evt-frank-01",
            "time": base_ms + 130000,
            "type": "LOGIN_ERROR",
            "realmId": "authdrift",
            "clientId": "authdrift-app",
            "userId": "usr-uuid-frank",
            "sessionId": "sess-frank-001",
            "ipAddress": "192.168.1.40",
            "details": {
                "username": "frank",
                "auth_method": "passkey",
                "error": "token_expired"
            }
        },
        {
            "id": "kc-evt-frank-02",
            "time": base_ms + 145000,
            "type": "LOGIN",
            "realmId": "authdrift",
            "clientId": "authdrift-app",
            "userId": "usr-uuid-frank",
            "sessionId": "sess-frank-001",
            "ipAddress": "192.168.1.40",
            "details": {
                "username": "frank",
                "auth_method": "password"
            }
        },

        # --- TC07: Grace - Unknown Authentication Method ---
        {
            "id": "kc-evt-grace-01",
            "time": base_ms + 160000,
            "type": "LOGIN",
            "realmId": "authdrift",
            "clientId": "authdrift-app",
            "userId": "usr-uuid-grace",
            "sessionId": "sess-grace-001",
            "ipAddress": "192.168.1.50",
            "details": {
                "username": "grace",
                "auth_method": "futuristic_quantum_handshake"
            }
        },
        {
            "id": "kc-evt-grace-02",
            "time": base_ms + 180000,
            "type": "LOGIN",
            "realmId": "authdrift",
            "clientId": "authdrift-app",
            "userId": "usr-uuid-grace",
            "sessionId": "sess-grace-001",
            "ipAddress": "192.168.1.50",
            "details": {
                "username": "grace",
                "auth_method": "password"
            }
        },

        # --- TC08: Heidi - Missing Device & Location Context (Safe Null Handling) ---
        {
            "id": "kc-evt-heidi-01",
            "time": base_ms + 200000,
            "type": "LOGIN_ERROR",
            "realmId": "authdrift",
            "clientId": "authdrift-app",
            "userId": "usr-uuid-heidi",
            "sessionId": "sess-heidi-001",
            "details": {
                "username": "heidi",
                "auth_method": "passkey",
                "error": "fido2_timeout"
            }
        },
        {
            "id": "kc-evt-heidi-02",
            "time": base_ms + 210000,
            "type": "LOGIN",
            "realmId": "authdrift",
            "clientId": "authdrift-app",
            "userId": "usr-uuid-heidi",
            "sessionId": "sess-heidi-001",
            "details": {
                "username": "heidi",
                "auth_method": "password"
            }
        },

        # --- TC09: Ivan - Normal Journey (No Downgrade) ---
        {
            "id": "kc-evt-ivan-01",
            "time": base_ms + 230000,
            "type": "LOGIN",
            "realmId": "authdrift",
            "clientId": "authdrift-app",
            "userId": "usr-uuid-ivan",
            "sessionId": "sess-ivan-001",
            "ipAddress": "192.168.1.60",
            "details": {
                "username": "ivan",
                "auth_method": "totp"
            }
        },
        {
            "id": "kc-evt-ivan-02",
            "time": base_ms + 240000,
            "type": "LOGIN",
            "realmId": "authdrift",
            "clientId": "authdrift-app",
            "userId": "usr-uuid-ivan",
            "sessionId": "sess-ivan-001",
            "ipAddress": "192.168.1.60",
            "details": {
                "username": "ivan",
                "auth_method": "totp"
            }
        }
    ]

    return events


def generate_okta_fixtures() -> List[Dict[str, Any]]:
    """
    Generates realistic Okta System Log fixtures demonstrating vendor-neutral ingestion.
    """
    base_iso = "2026-10-30T14:10:"
    return [
        {
            "uuid": "okta-evt-001",
            "published": f"{base_iso}00.000Z",
            "eventType": "user.authentication.auth_via_mfa",
            "outcome": {"result": "FAILURE", "reason": "FIDO2 user verification failed"},
            "actor": {"id": "00u_alex_01", "alternateId": "alex@company.com"},
            "client": {
                "device": "MacBookPro18,1",
                "geographicalContext": {"city": "San Francisco", "country": "United States"}
            },
            "authenticationContext": {
                "credentialProvider": "FIDO2 (WebAuthn)",
                "externalSessionId": "okta-sess-99"
            }
        },
        {
            "uuid": "okta-evt-002",
            "published": f"{base_iso}20.000Z",
            "eventType": "user.authentication.authenticate",
            "outcome": {"result": "SUCCESS"},
            "actor": {"id": "00u_alex_01", "alternateId": "alex@company.com"},
            "client": {
                "device": "MacBookPro18,1",
                "geographicalContext": {"city": "San Francisco", "country": "United States"}
            },
            "authenticationContext": {
                "credentialProvider": "PASSWORD",
                "externalSessionId": "okta-sess-99"
            }
        }
    ]


def save_sample_data(sample_dir: str = "sample-data") -> None:
    os.makedirs(sample_dir, exist_ok=True)
    kc_events = generate_keycloak_fixtures()
    kc_path = os.path.join(sample_dir, "keycloak_events.json")
    with open(kc_path, "w", encoding="utf-8") as f:
        json.dump(kc_events, f, indent=2)

    okta_events = generate_okta_fixtures()
    okta_path = os.path.join(sample_dir, "okta_events.json")
    with open(okta_path, "w", encoding="utf-8") as f:
        json.dump(okta_events, f, indent=2)


if __name__ == "__main__":
    save_sample_data()
    print("Sample data fixtures generated successfully.")

