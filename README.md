# AuthDrift: Authentication Assurance Drift Detection and Analysis

AuthDrift is a lightweight, vendor-neutral monitoring layer for analysing **authentication assurance** across a user's entire authentication journey. 

Rather than viewing authentication events as isolated logs (e.g., "login failed," "password successful"), AuthDrift reconstructs a connected timeline. By doing so, it can detect when a user begins with a strong authentication method but falls back to a weaker one within the same session—a phenomenon we call **Authentication Assurance Drift**.

---

## 🛑 Critical Project Rule: NO AI / ML

This project is explicitly a deterministic, rule-based system. **It is NOT an AI or Machine Learning project.**

- **No ML models** (TensorFlow, PyTorch, scikit-learn, etc.).
- **No LLMs or AI APIs**.
- **No ML concept drift**. The term "drift" in AuthDrift refers strictly to a reduction in relative authentication strength (e.g., Passkey → Password).
- **No ML-based anomaly detection.**

---

## The Core Problem & Solution

Modern identity systems generate thousands of individual events. A passkey failure might be normal. A password login might be permitted. But a *passkey failure followed immediately by a password login* represents a meaningful reduction in authentication assurance. 

AuthDrift does **not** replace existing Identity Providers (like Entra, Okta, or Keycloak) or SIEM systems. Instead, it acts as a correlation layer that:
1. Collects authentication events.
2. Normalizes them into a common schema.
3. Assigns a relative assurance score (HIGH, MEDIUM, LOW).
4. Reconstructs the chronological journey.
5. Flags and explains assurance degradation.

> **Note:** A drift is *not* automatically an attack. Legitimate account recovery or new device migrations can cause drift. AuthDrift explains the transition without blindly labeling it as a compromise.

---

## The Core Pipeline (First Prototype)

The initial 3-objective prototype focuses entirely on the core logic:

`Keycloak (Raw Events) → Event Normalization → Assurance Assignment → Journey Reconstruction → Basic Drift Detection → Testing`

### 1. Common Event Schema
A frozen, shared interface between all modules:
`event_id, user_id, timestamp, event_type, authentication_method, outcome, device_id, location, authenticator_id`

### 2. Assurance Assignment
Methods are mapped to relative assurance levels.
*Example: Passkey = HIGH, OTP = MEDIUM, Password = LOW*

### 3. Journey Reconstruction
Chronological grouping of a single user's session.
*Example: Passkey FAILED → Password SUCCESS → New Device*

### 4. Drift Detection (Rule-Based)
**Rule**: IF a stronger authentication method is followed by a weaker authentication method WITHIN THE SAME JOURNEY, THEN flag an authentication assurance decrease.

---

## Test Scenarios

The prototype validates against controlled Keycloak scenarios:
* **TC01**: Known-device passkey success (No drift).
* **TC02**: Passkey → Password fallback (Drift detected).
* **TC03**: Passkey failure → Password success (Drift detected).
* **TC04**: Weaker authentication → New device context.
* **TC05**: Downgrade → New authenticator registration.

---

## Team Responsibilities & Branches

The project is divided across four feature branches before integrating into `main`.

| Team Member | Branch | Responsibilities |
| :--- | :--- | :--- |
| **Balaa** | `balaa/assurance-detection` | Assurance model, mapping logic, basic drift detection, detection output contracts. |
| **Tashi** | `tashi/keycloak-events` | Keycloak setup, authentication scenarios, raw event extraction, schema normalization. |
| **Rohan** | `rohan/journey-ui` | Journey reconstruction, timeline representation, UI display of detection results. |
| **Varun** | `varun/testing` | Test cases, test data, expected/actual comparison, regression validation. |

---

## Git Workflow

1. **Do not push directly to `main`.**
2. Check out your assigned branch: `git checkout <branch-name>`
3. Make your localized changes and commit with clear messages.
4. Push to your branch and open a Pull Request against `main`.
5. Review interface compatibility with the team before merging.

---

## Quick Start

1. Clone the repository and switch to your branch.
2. Install the shared dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Run the test suite (once Varun's tests are integrated):
   ```bash
   pytest tests/
   ```