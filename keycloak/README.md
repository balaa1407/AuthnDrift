# AuthDrift: Keycloak Setup & Controlled Scenarios

This directory contains the reproducible Keycloak configuration, realm export, event extractor client, and scenario fixtures for AuthDrift.

---

## 1. Reproducible Keycloak Environment

### Quick Start with Docker Compose
To launch Keycloak with the preconfigured AuthDrift realm:

```bash
docker compose -f keycloak/docker-compose.yml up -d
```

- **Keycloak Admin Console**: `http://localhost:8080/admin`
- **Username**: `admin`
- **Password**: `admin`
- **Preconfigured Realm**: `authdrift`

---

## 2. Preconfigured Realm & Test Users

The realm definition (`authdrift-realm.json`) automatically:
1. Enables **User Event Logging** (`eventsEnabled: true`) and JBoss logging (`eventsListeners: ["jboss-logging"]`).
2. Configures event types: `LOGIN`, `LOGIN_ERROR`, `REGISTER`, `UPDATE_PASSWORD`, `REGISTER_AUTHENTICATOR`, etc.
3. Sets up test client: `authdrift-app` (public client for redirect tests).
4. Creates controlled test users:

| Username | Configured Credentials | Purpose in Prototype |
| :--- | :--- | :--- |
| **alice** | WebAuthn / Passkey | TC01: Known-device passkey success (High assurance, no drift). |
| **bob** | WebAuthn Passkey + Password | TC02: Passkey failure followed by password fallback (Assurance drift). |
| **carol** | WebAuthn Passkey + Password | TC03: Passkey failure + password success on new device. |
| **dave** | Password | TC04: Repeated failed login attempts. |
| **eve** | Password + WebAuthn Register | TC05: Downgrade followed by rogue authenticator registration. |
| **frank** | Password | TC06: Legitimate recovery / migration scenario. |

---

## 3. Extracting Events from Keycloak

The event extractor client (`keycloak/keycloak_extractor.py`) queries Keycloak's Admin REST API:

```python
from keycloak.keycloak_extractor import KeycloakEventExtractor

extractor = KeycloakEventExtractor(
    base_url="http://localhost:8080",
    realm="authdrift",
    admin_username="admin",
    admin_password="admin"
)

# Fetch user events
events = extractor.fetch_events(max_events=100)

# Export to JSON
extractor.export_events_to_file("sample-data/keycloak_live_events.json")
```

---

## 4. Repeatable Offline Test Fixtures

In environments where Docker is not installed or Keycloak is offline, run the reproducible fixture generator:

```bash
python keycloak/generate_keycloak_fixtures.py
```

This generates:
- `sample-data/keycloak_events.json` (Realistic Keycloak events for TC01–TC09)
- `sample-data/okta_events.json` (Vendor-neutral Okta System Logs)

---

## 5. Environment Capabilities & Limitations

1. **Docker Availability**: In virtual or sandbox environments where Docker is not installed, the pipeline executes against the realistic exported Keycloak event schema in `sample-data/keycloak_events.json`.
2. **Passkey Browser Ceremony**: Generating live passkey WebAuthn ceremonies via headless CLI requires browser WebAuthn virtual authenticator emulation (e.g. Chrome DevTools Protocol or Puppeteer). For headless CI/CD, the extractor and fixture generator produce exact Keycloak event payloads emitted by the Keycloak WebAuthn authenticator execution flow.
3. **Missing Fields**: Keycloak events omit `device_id` by default unless extracted from User-Agent headers or client context. AuthDrift cleanly handles missing optional fields as `None` without fabricating data.

