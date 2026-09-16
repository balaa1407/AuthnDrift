# AuthDrift: Authentication Assurance Drift Detection and Analysis

AuthDrift is a lightweight, vendor-neutral monitoring layer for analysing authentication assurance across a user's authentication journey. It identifies and explains a meaningful reduction in relative authentication assurance during an authentication journey (e.g. falling back from a Passkey to a Password).

**IMPORTANT NOTE**: This is explicitly a deterministic, rule-based prototype. It does **NOT** use Machine Learning, AI, or statistical models. Authentication assurance drift is entirely distinct from ML concept drift.

## Core Prototype Objectives

1. **Collect and Normalize Events**: Extract authentication events from Keycloak into a common schema.
2. **Assurance Assignment**: Assign relative assurance levels to methods (e.g. Passkey=HIGH, Password=LOW).
3. **Journey Reconstruction**: Chronologically group events into unified authentication journeys.
4. **Basic Drift Detection**: Identify when a strong authentication method is followed by a weaker authentication method within the same journey.

## Development Constraints

- **No ML/AI**: No PyTorch, TensorFlow, LLMs, or ML pipelines.
- **Explainable Rules**: All drift detections are deterministically triggered and must provide a textual reason for the alert.
- **Not a SIEM Replacement**: AuthDrift is a correlation layer, not a replacement for Entra, Okta, or existing Identity Providers.

## Branch Strategy

- `main` - Protected branch containing the integrated prototype
- `balaa/assurance-detection` - Assurance models and detection engine
- `tashi/keycloak-events` - Keycloak setup and event extraction/normalization
- `rohan/journey-ui` - Journey reconstruction and dashboard
- `varun/testing` - Testing and validation suites

## Getting Started

1. Check out your respective branch.
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Run the test suite:
   ```bash
   pytest tests/
   ```