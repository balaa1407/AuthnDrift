# AuthDrift — Core Security & Detection Engine Architecture

This document provides the formal architectural specification, academic justifications, detection heuristics, and verification methodology for the core security intelligence layer of **AuthDrift: Authentication Assurance Drift Detection and Analysis**.

---

## 1. Relative Authentication Assurance Model (Objective 2)

### 1.1 Technical Distinction from Formal NIST SP 800-63B AAL
In NIST Special Publication 800-63B (*Digital Identity Guidelines: Authentication and Lifecycle Management*), Authenticator Assurance Levels (AAL1, AAL2, AAL3) characterize the **entire authentication transaction and lifecycle process**. A formal AAL rating requires specific combinations of primary and secondary factors, secure channel properties, verifier impersonation resistance, credential replay resistance, and verifier compromise protection.

**AuthDrift's Relative Model:**
AuthDrift models the **relative standalone assurance contribution** of individual authenticators and challenge mechanisms rather than certifying an end-to-end AAL rating. Authenticators are classified into three strictly ordered tiers:

$$\text{LOW (1)} < \text{MEDIUM (2)} < \text{HIGH (3)}$$

### 1.2 Tier Definitions and Authenticator Mapping

| Tier | Value | Cryptographic & Architectural Characteristics | Supported Authenticator Methods | Academic & Standards Justification |
| :--- | :---: | :--- | :--- | :--- |
| **HIGH** | `3` | Asymmetric public-key cryptography, hardware proof-of-possession, origin-binding, verifier-impersonation resistance. | `passkey`, `fido2`, `webauthn`, `hardware_token`, `security_key`, `u2f`, `client_cert`, `client_certificate` | NIST SP 800-63B criteria for phishing-resistant authenticators. Private keys remain protected within hardware enclaves or platform authenticators, preventing credential relay or harvest. |
| **MEDIUM** | `2` | Out-of-band delivery channels or shared-secret symmetric algorithms. Multi-factor capable but vulnerable to adversary-in-the-middle (AiTM) proxy phishing. | `totp`, `authenticator_app`, `otp`, `sms_otp`, `sms`, `email_otp`, `push_notification`, `push` | NIST SP 800-63B criteria for out-of-band and OTP tokens. Valid for single sessions but susceptible to reverse-proxy interception, SIM-swapping, SS7 interception, or push fatigue. |
| **LOW** | `1` | Single-factor memorized secrets, short static PINs, or legacy knowledge challenges. No proof of physical possession. | `password`, `pin`, `knowledge_based`, `security_questions` | NIST SP 800-63B criteria for memorized secrets. Susceptible to brute force, credential stuffing, credential reuse, and harvesting. Knowledge-based verification is formally prohibited. |

### 1.3 Defensive Fallback & Dynamic Extensibility
- **Fail-Closed Default**: Any unrecognized or missing authentication method is defensively classified as `AssuranceLevel.LOW` with `is_recognized=False` to prevent unwarranted elevation of unverified methods.
- **Dynamic Registration**: New authentication mechanisms (e.g. enterprise biometrics, custom smartcards) can be registered at runtime via `AssuranceModel.register_method(method, level, rationale)`.

---

## 2. Authentication Assurance Drift Detection (Objective 3)

### 2.1 The Central Threat Sequence
AuthDrift addresses scenarios where an identity is configured with phishing-resistant high-assurance authenticators, yet the system allows fallback to lower-assurance methods:

$$\text{Passkey (HIGH)} \xrightarrow{\text{FAILURE}} \text{Password (LOW)} \xrightarrow{\text{SUCCESS}} \text{New Device} \xrightarrow{\text{DETECTED}} \text{Rogue Authenticator} \xrightarrow{\text{REGISTERED}}$$

While each authentication attempt may appear valid or expected in isolation, the chronological journey reveals a critical **assurance degradation** that warrants real-time risk evaluation.

### 2.2 Transition Typology & Heuristic Rules

1. **`RULE_FAILED_STRONG_SUCCESS_WEAK`**:
   - Triggered when a higher-assurance authenticator fails and is followed by successful authentication using a strictly lower-assurance fallback (e.g. Passkey failure followed by Password success).
   - The engine strictly verifies that the preceding failed method had a higher assurance value than the subsequent successful method (`failed_assurance > current_assurance`).

2. **`RULE_MULTI_FAILURE_FALLBACK`**:
   - Triggered when multiple failed authentication attempts ($\ge 2$) precede an assurance downgrade.
   - Captures attacker credential guessing or repeated failed biometric challenges before dropping to legacy fallbacks.

3. **`RULE_DOWNGRADE_GENERAL`**:
   - Captures an assurance reduction without an explicit preceding failure within the analyzed journey window (e.g. moving from a WebAuthn session directly to a single-factor password challenge).

4. **`RULE_STEP_UP_AUTHENTICATION`**:
   - Informational classification triggered when a journey elevates assurance (e.g. Password login followed by Passkey step-up verification).
   - Does not flag drift (`drift_detected=False`).

5. **`RULE_REPEATED_FAILURES_SAME_METHOD`**:
   - Captures repeated authentication failures ($\ge 2$) occurring at the same assurance tier (e.g. password brute-force).
   - Strictly isolated from assurance drift (`drift_detected=False`), routing to behavioral failure counters rather than drift alerts.

### 2.3 Configuration Parameters
- `min_assurance_drop` (default: `1`): Minimum tier reduction required to trigger drift.
- `detect_any_downgrade` (default: `True`): Whether general downgrades without failure trigger alerts.
- `require_prior_failure` (default: `False`): When enabled, requires an explicit failure of the stronger method before flagging drift.
- `track_step_ups` (default: `True`): Whether legitimate step-up transitions are explicitly reported.

---

## 3. Journey Assumptions & Boundary Isolation

1. **Deterministic Chronological Sorting**: Events are defensively sorted by `timestamp`. Missing timestamps default to `datetime.min` to guarantee deterministic evaluation order.
2. **Event Deduplication**: Log replays and duplicate network deliveries with identical `event_id`s are deduplicated to prevent artificial failure amplification.
3. **Lifecycle Event Isolation**: Account-management and lifecycle events (`REGISTER_AUTHENTICATOR`, `UPDATE_CREDENTIAL`, `DELETE_CREDENTIAL`, `LOGOUT`) are excluded from participating as authentication downgrade events in drift detection. They participate strictly in contextual correlation.
4. **Single-User Isolation**: Every analyzed journey must represent a single identity. Multiple `user_id` values in a single journey raise `ValueError` to prevent cross-tenant or cross-user contamination.

---

## 4. Contextual Correlation Architecture (Objective 3)

The `ContextAnalyzer` extracts and correlates environmental signals strictly using available event data without fabricating missing attributes:

1. **Device Baseline Comparison**:
   - If a known-device baseline is configured for the user, any observed device ID not in the baseline sets `is_new_device = True`.
   - If all observed devices match the baseline, `is_new_device = False`.
   - If no baseline is provided or `device_id` is missing, `is_new_device = None`.
   - **Sticky Anomaly Handling**: An unfamiliar device observed anywhere in a multi-event journey persists as `is_new_device = True`.

2. **Location Baseline Comparison**:
   - Evaluated against known geographic locations using sticky anomaly tracking. Missing location fields or baselines strictly evaluate to `None`.

3. **Authenticator Registration Correlation**:
   - Detects when an authenticator enrollment (`REGISTER_AUTHENTICATOR`, `CREDENTIAL_REGISTER`) occurs during the session.
   - Identified as a critical persistence indicator when following an assurance downgrade.

4. **Failure Counting**:
   - Robustly tallies failed authentication attempts without double-counting deduplicated events or crashing on null outcomes.

---

## 5. Mathematical Risk Scoring Model (Objective 4)

### 5.1 Formulation
The risk score $S \in [0, 100]$ is computed as a transparent, additive heuristic:

$$S = \min\left(100, \sum_{i} w_i \cdot \mathbf{1}_{\text{factor}_i}\right)$$

Where $\mathbf{1}_{\text{factor}_i} \in \{0, 1\}$ indicates the empirical presence of verified factor $i$.

### 5.2 Factor Weights & Operational Rationale

| Risk Factor | Weight ($w_i$) | Operational Rationale |
| :--- | :---: | :--- |
| **Assurance Downgrade (HIGH $\to$ LOW)** | `40` | Major degradation from phishing-resistant credentials to legacy memorized secrets. |
| **Assurance Downgrade (HIGH $\to$ MEDIUM)** | `20` | Moderate degradation from phishing-resistant to shared-secret out-of-band credentials. |
| **Assurance Downgrade (MEDIUM $\to$ LOW)** | `15` | Degradation from multi-factor out-of-band to single-factor memorized secrets. |
| **Preceding Strong Method Failure** | `15` | Strong method was actively challenged and failed prior to falling back to a weaker method. |
| **Repeated Failures ($\ge 2$ attempts)** | `10` | Brute force or repeated guessing signal preceding authentication. |
| **New Device Detected** | `20` | Authentication initiated from an unrecognized device hardware identifier. |
| **Changed Location** | `15` | Authentication initiated from an unfamiliar geographic baseline. |
| **Authenticator Registered Post-Downgrade** | `25` | High-priority persistence indicator: attacker adding secondary credential to cement access. |

### 5.3 Severity Boundaries & Operational Priorities
- **`LOW` (0–29)**: Standard or low-risk authentication. Informational status.
- **`MEDIUM` (30–59)**: Moderate anomaly (e.g. general downgrade or repeated failures). Requires routine review.
- **`HIGH` (60–79)**: Significant degradation combined with contextual anomalies (e.g. failed passkey + password on new device). Requires security investigation.
- **`CRITICAL` (80–100)**: Compound multi-factor threat (e.g. downgrade + new device + credential registration). Immediate high-priority triage.

---

## 6. Explainable Alert Structure (Objective 4)

Every `SecurityAlert` output provides human-readable explanations and structured fields for SIEM and dashboard consumption:

```python
@dataclass
class SecurityAlert:
    alert_id: str                      # Unique traceable alert UUID
    user_id: str                       # Identity analyzed
    timestamp: datetime                # Journey completion timestamp
    drift_detected: bool               # Whether an assurance downgrade occurred
    drift_result: DriftResult          # Full transition and method details
    context_evidence: ContextEvidence  # Empirical signals observed
    risk_assessment: RiskAssessment    # Deterministic score and factor breakdown
    methods_involved: List[str]        # Chronologically ordered methods
    explanation: str                   # Human-readable audit narrative
    is_actionable: bool                # Triage flag (drift or score >= 50)
    session_id: Optional[str]          # Correlated session ID
    priority: str                      # INFORMATIONAL | INVESTIGATION_REQUIRED | HIGH_PRIORITY
```

### Academic Caveat on Active Compromise
All generated alerts include an explicit caveat:
> *"Notice: An assurance downgrade is not definitive proof of an active compromise. Legitimate factors such as forgotten hardware authenticators, browser incompatibility, or device migration can trigger fallback. Verification is recommended based on risk severity."*

---

## 7. Verification Methodology & Test Coverage

The test suite consists of **64 automated pytest cases** covering unit behavior, regression edge cases, and 10 controlled scenarios:

- **TC01**: Known-device passkey success (Score 0, LOW severity, no drift).
- **TC02**: Failed passkey followed by password fallback (HIGH $\to$ LOW drift detected).
- **TC03**: Failed passkey, password success on new device (Compound risk, HIGH/CRITICAL severity).
- **TC04**: Repeated password failures (Failure counting without false assurance drift).
- **TC05**: Downgrade followed by authenticator registration (CRITICAL persistence alert).
- **TC06**: Legitimate recovery or device migration (Caveat verification).
- **TC07**: Unknown authentication method (Fail-closed LOW assignment).
- **TC08**: Missing device/location context (Null handling without fabricated values).
- **TC09**: Normal multi-step journey (TOTP $\to$ TOTP, no false drift).
- **TC10**: Cross-user journey isolation (Contaminated journeys rejected).
- **Edge Cases**: Step-up followed by downgrade, weak failure followed by strong success, multi-failure across methods, all configuration toggles, out-of-order events, and duplicate event deduplication.

---

## 8. Known Limitations & Prototype Boundaries

1. **Controlled Environment Scope**: The prototype relies on normalized event streams conforming to the common `AuthenticationEvent` schema. It does not perform active network packet sniffing or in-line proxying.
2. **Stateless Journey Scope**: Journeys are evaluated within bounded batches or sessions. Long-term longitudinal behavioral baselining across months is handled via the baseline set inputs (`known_devices`, `known_locations`).
3. **Heuristic Risk Calibration**: Risk scores reflect transparent, expert-configured heuristic weights rather than machine learning models or statistical probability distributions.
