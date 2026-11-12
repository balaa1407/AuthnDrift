"""
AuthDrift: Unit Tests for LLM Calibration & Fallback Memory (Person 1 Task 3).
Verifies:
1. FallbackMemoryStore profile management, subnet continuity, and fallback history.
2. LLMContextBuilder research-grounded prompt assembly and structured JSON schema.
3. LLMCalibrator deterministic heuristic calibration across Cases 1-5 and fail-closed safety.
4. FastAPI endpoints for LLM memory and calibration.
"""

from datetime import datetime, timezone
import pytest
from fastapi.testclient import TestClient

from backend.api import app
from backend.llm_calibration.fallback_memory import FallbackMemoryStore, UserFallbackProfile
from backend.llm_calibration.context_builder import LLMContextBuilder
from backend.llm_calibration.calibrator import LLMCalibrator
from backend.models.event import AuthenticationEvent, AuthenticationJourney
from backend.models.detection import ContextEvidence, DriftResult, SecurityAlert, RiskAssessment, RiskSeverity


client = TestClient(app)


class TestFallbackMemoryStore:
    """Verifies baseline registration, subnet matching, and profile persistence."""

    def test_baseline_registration_and_retrieval(self):
        store = FallbackMemoryStore()
        prof = store.register_baseline(
            user_id="user_john",
            device_id="laptop-john-work",
            ip_address="10.20.30.40",
            location="Bengaluru, IN"
        )
        assert prof.user_id == "user_john"
        assert prof.primary_device_id == "laptop-john-work"
        assert prof.primary_ip_address == "10.20.30.40"
        assert "10.20.30.40" in prof.known_ips
        assert "laptop-john-work" in prof.known_devices

        retrieved = store.get_profile("user_john")
        assert retrieved is not None
        assert retrieved.user_id == "user_john"

    def test_device_matching_exact(self):
        store = FallbackMemoryStore()
        store.register_baseline(
            user_id="user_john",
            device_id="laptop-john-work",
            ip_address="10.20.30.40"
        )
        assert store.is_primary_device("user_john", "laptop-john-work") is True
        assert store.is_primary_device("user_john", "unfamiliar-laptop") is False
        assert store.is_primary_device("user_john", None) is False

    def test_ip_matching_and_subnet_continuity(self):
        store = FallbackMemoryStore()
        store.register_baseline(
            user_id="user_john",
            device_id="laptop-john-work",
            ip_address="192.168.1.100"
        )
        # Exact IP match
        assert store.is_primary_ip("user_john", "192.168.1.100") is True
        # Same /24 subnet match (DHCP hop)
        assert store.is_primary_ip("user_john", "192.168.1.150") is True
        # Different subnet
        assert store.is_primary_ip("user_john", "192.168.2.100") is False
        assert store.is_primary_ip("user_john", None) is False

    def test_record_fallback_event_updates_stats(self):
        store = FallbackMemoryStore()
        store.record_fallback_event(
            user_id="user_mary",
            from_method="passkey",
            to_method="password",
            device_id="dev-mary",
            ip_address="10.0.0.5",
            outcome="SUCCESS"
        )
        prof = store.get_profile("user_mary")
        assert prof is not None
        assert prof.successful_recoveries == 1
        assert prof.total_fallbacks == 1
        assert len(prof.recovery_history) == 1
        assert prof.recovery_history[0]["from_method"] == "passkey"


class TestLLMContextBuilder:
    """Verifies that LLM prompts contain academic citations, grounding context, and JSON schema."""

    def test_scenario_prompt_contains_citations_and_structure(self):
        builder = LLMContextBuilder()
        journey = AuthenticationJourney(
            user_id="alice",
            events=[
                AuthenticationEvent(
                    event_id="e1",
                    user_id="alice",
                    timestamp=datetime.now(timezone.utc),
                    event_type="LOGIN_ERROR",
                    authentication_method="passkey",
                    outcome="FAILURE",
                    device_id="macbook-alice",
                    ip_address="10.0.0.1"
                ),
                AuthenticationEvent(
                    event_id="e2",
                    user_id="alice",
                    timestamp=datetime.now(timezone.utc),
                    event_type="LOGIN",
                    authentication_method="password",
                    outcome="SUCCESS",
                    device_id="macbook-alice",
                    ip_address="10.0.0.1"
                )
            ]
        )
        evidence = ContextEvidence(
            is_new_device=False,
            device_id="macbook-alice",
            ip_address="10.0.0.1",
            primary_device="macbook-alice",
            primary_ip="10.0.0.1",
            is_primary_device_matched=True,
            is_primary_ip_matched=True,
            case_category="CASE_1_SAME_DEVICE_SAME_IP"
        )
        prompt = builder.build_scenario_prompt(
            journey=journey,
            evidence=evidence,
            user_profile={"user_id": "alice", "primary_device": "macbook-alice"}
        )

        assert "Lyastani et al." in prompt
        assert "Wiefling et al." in prompt
        assert "Bonneau et al." in prompt
        assert "CASE_1_SAME_DEVICE_SAME_IP" in prompt
        assert "classification" in prompt
        assert "confidence" in prompt


class TestLLMCalibrator:
    """Verifies deterministic heuristic calibration for all cases and fail-closed safety."""

    def setup_method(self):
        self.calibrator = LLMCalibrator()

    def test_calibrates_case_1_as_genuine_recovery(self):
        decision = self.calibrator.evaluate_journey(
            user_id="alice",
            journey_events=[
                {"method": "passkey", "outcome": "FAILURE"},
                {"method": "password", "outcome": "SUCCESS"}
            ],
            observed_device="dev-1",
            observed_ip="192.168.1.10",
            primary_device="dev-1",
            primary_ip="192.168.1.10",
            case_category="CASE_1_SAME_DEVICE_SAME_IP"
        )
        assert decision.classification == "GENUINE_RECOVERY"
        assert decision.is_genuine_recovery is True
        assert decision.suppress_drift is True
        assert decision.recommended_severity == "LOW"
        assert decision.confidence >= 0.9
        assert "Wiefling et al." in decision.academic_justification

    def test_calibrates_case_2_as_adversarial_drift(self):
        decision = self.calibrator.evaluate_journey(
            user_id="bob",
            journey_events=[
                {"method": "passkey", "outcome": "FAILURE"},
                {"method": "password", "outcome": "SUCCESS"}
            ],
            observed_device="unfamiliar-box",
            observed_ip="192.168.1.10",
            primary_device="dev-bob",
            primary_ip="192.168.1.10",
            case_category="CASE_2_DIFF_DEVICE_SAME_IP"
        )
        assert decision.classification == "ADVERSARIAL_DRIFT"
        assert decision.is_genuine_recovery is False
        assert decision.suppress_drift is False
        assert decision.recommended_severity in ["HIGH", "CRITICAL"]

    def test_calibrates_case_5_as_critical_persistence(self):
        decision = self.calibrator.evaluate_journey(
            user_id="carol",
            journey_events=[
                {"method": "passkey", "outcome": "FAILURE"},
                {"method": "password", "outcome": "SUCCESS"},
                {"method": "webauthn", "outcome": "SUCCESS", "event_type": "REGISTER_AUTHENTICATOR"}
            ],
            observed_device="attacker-pc",
            observed_ip="45.141.215.82",
            primary_device="corp-laptop",
            primary_ip="10.0.0.1",
            case_category="CASE_5_ROGUE_AUTHENTICATOR_REGISTRATION"
        )
        assert decision.classification == "ADVERSARIAL_DRIFT"
        assert decision.recommended_severity == "CRITICAL"
        assert decision.suppress_drift is False

    def test_calibrates_missing_context_as_uncertain_fail_closed(self):
        decision = self.calibrator.evaluate_journey(
            user_id="dave",
            journey_events=[
                {"method": "passkey", "outcome": "FAILURE"},
                {"method": "password", "outcome": "SUCCESS"}
            ],
            observed_device=None,
            observed_ip=None,
            primary_device="corp-laptop",
            primary_ip="10.0.0.1"
        )
        assert decision.classification == "UNCERTAIN_MISSING_CONTEXT"
        assert decision.is_genuine_recovery is False
        assert decision.suppress_drift is False


class TestLLMAPIExtensions:
    """Verifies FastAPI endpoints for Person 1 LLM calibration & fallback memory."""

    def test_register_and_get_fallback_memory_via_api(self):
        resp = client.post(
            "/api/llm/register-baseline",
            json={
                "user_id": "test_api_user",
                "primary_device": "laptop-api-01",
                "primary_ip": "10.50.60.70"
            }
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "success"
        assert data["user_id"] == "test_api_user"
        assert data["primary_device"] == "laptop-api-01"

        get_resp = client.get("/api/llm/fallback-memory")
        assert get_resp.status_code == 200
        get_data = get_resp.json()
        assert "profiles" in get_data
        assert "test_api_user" in get_data["profiles"]
        assert get_data["profiles"]["test_api_user"]["primary_device"] == "laptop-api-01"

    def test_calibrate_journey_via_api(self):
        # 1. Load scenario so current_result is populated
        load_resp = client.post("/api/scenarios/client_recovery/load")
        assert load_resp.status_code == 200

        # 2. Register baseline for bob in fallback memory
        client.post(
            "/api/llm/register-baseline",
            json={
                "user_id": "bob",
                "primary_device": "laptop-01",
                "primary_ip": "192.168.1.10"
            }
        )

        # 3. Calibrate bob's recovery journey
        resp = client.post(
            "/api/llm/calibrate-journey",
            json={
                "user_id": "bob"
            }
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["user_id"] == "bob"
        assert data["classification"] == "GENUINE_RECOVERY"
        assert data["is_drift_alert_suppressed"] is True
        assert data["case_category"] == "CASE_1_SAME_DEVICE_SAME_IP"
