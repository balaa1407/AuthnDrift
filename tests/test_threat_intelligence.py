"""
AuthDrift: Unit and Integration Test Suite for IP Threat Intelligence.
Validates AbuseIPDB provider, reputation service, caching, failure resilience,
risk engine factor 7, alert priority escalation, and pipeline integration using mocks.
"""

import time
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch
import pytest

from backend.threat_intelligence.base import (
    IPReputationResult,
    STATUS_KNOWN_MALICIOUS,
    STATUS_SUSPICIOUS,
    STATUS_CLEAN,
    STATUS_PRIVATE,
    STATUS_UNKNOWN,
)
from backend.threat_intelligence.abuseipdb import AbuseIPDBProvider
from backend.threat_intelligence.reputation_service import IPReputationService
from backend.models.event import AuthenticationEvent
from backend.models.detection import RiskSeverity, AlertPriority, ContextEvidence, DriftResult
from backend.risk.risk_config import RiskEngineConfig
from backend.risk.risk_engine import RiskEngine
from backend.alerts.alert_generator import AlertGenerator
from backend.pipeline.pipeline import AuthDriftPipeline


class TestAbuseIPDBProvider:
    """Tests for the AbuseIPDB provider client."""

    def test_missing_api_key_returns_unknown(self):
        provider = AbuseIPDBProvider(api_key="")
        result = provider.check_ip("8.8.8.8")
        assert result.status == STATUS_UNKNOWN
        assert result.ip_address == "8.8.8.8"
        assert result.provider == "AbuseIPDB"
        assert result.abuse_confidence_score is None

    @patch("requests.get")
    def test_successful_lookup_malicious(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "data": {
                "ipAddress": "118.25.6.39",
                "abuseConfidenceScore": 85,
                "totalReports": 34,
                "lastReportedAt": "2026-10-30T12:00:00Z"
            }
        }
        mock_get.return_value = mock_resp

        provider = AbuseIPDBProvider(api_key="test-api-key")
        result = provider.check_ip("118.25.6.39")

        assert result.status == STATUS_KNOWN_MALICIOUS
        assert result.abuse_confidence_score == 85
        assert result.total_reports == 34
        assert result.last_reported_at == "2026-10-30T12:00:00Z"
        assert result.provider == "AbuseIPDB"

        # Verify API key is passed in headers
        args, kwargs = mock_get.call_args
        assert kwargs["headers"]["Key"] == "test-api-key"

    @patch("requests.get")
    def test_successful_lookup_suspicious(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "data": {
                "ipAddress": "142.250.190.46",
                "abuseConfidenceScore": 35,
                "totalReports": 5,
                "lastReportedAt": "2026-10-29T10:00:00Z"
            }
        }
        mock_get.return_value = mock_resp

        provider = AbuseIPDBProvider(api_key="test-api-key")
        result = provider.check_ip("142.250.190.46")

        assert result.status == STATUS_SUSPICIOUS
        assert result.abuse_confidence_score == 35
        assert result.total_reports == 5

    @patch("requests.get")
    def test_successful_lookup_clean(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "data": {
                "ipAddress": "8.8.8.8",
                "abuseConfidenceScore": 0,
                "totalReports": 0,
                "lastReportedAt": None
            }
        }
        mock_get.return_value = mock_resp

        provider = AbuseIPDBProvider(api_key="test-api-key")
        result = provider.check_ip("8.8.8.8")

        assert result.status == STATUS_CLEAN
        assert result.abuse_confidence_score == 0
        assert result.total_reports == 0

    @patch("requests.get")
    def test_rate_limit_handled_gracefully(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 429
        mock_resp.text = "Too Many Requests"
        mock_get.return_value = mock_resp

        provider = AbuseIPDBProvider(api_key="test-api-key")
        result = provider.check_ip("8.8.8.8")

        assert result.status == STATUS_UNKNOWN
        assert result.abuse_confidence_score is None

    @patch("requests.get")
    def test_unauthorized_key_handled_gracefully(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 401
        mock_resp.text = "Unauthorized"
        mock_get.return_value = mock_resp

        provider = AbuseIPDBProvider(api_key="invalid-key")
        result = provider.check_ip("8.8.8.8")

        assert result.status == STATUS_UNKNOWN

    @patch("requests.get")
    def test_timeout_handled_gracefully(self, mock_get):
        import requests
        mock_get.side_effect = requests.exceptions.ConnectTimeout("Connection timed out")

        provider = AbuseIPDBProvider(api_key="test-api-key")
        result = provider.check_ip("8.8.8.8")

        assert result.status == STATUS_UNKNOWN

    @patch("requests.get")
    def test_network_error_handled_gracefully(self, mock_get):
        import requests
        mock_get.side_effect = requests.exceptions.ConnectionError("Network unreachable")

        provider = AbuseIPDBProvider(api_key="test-api-key")
        result = provider.check_ip("8.8.8.8")

        assert result.status == STATUS_UNKNOWN

    @patch("requests.get")
    def test_malformed_json_handled_gracefully(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.side_effect = ValueError("Invalid JSON response")
        mock_get.return_value = mock_resp

        provider = AbuseIPDBProvider(api_key="test-api-key")
        result = provider.check_ip("8.8.8.8")

        assert result.status == STATUS_UNKNOWN


class TestIPReputationService:
    """Tests for the service wrapper, IP validation, and caching."""

    def test_private_ip_is_skipped(self):
        service = IPReputationService()
        for priv_ip in ["192.168.1.1", "10.0.0.1", "172.16.0.5"]:
            result = service.get_ip_reputation(priv_ip)
            assert result.status == STATUS_PRIVATE
            assert result.abuse_confidence_score == 0
            assert result.ip_address == priv_ip

    def test_loopback_and_link_local_skipped(self):
        service = IPReputationService()
        for local_ip in ["127.0.0.1", "::1", "169.254.1.1"]:
            result = service.get_ip_reputation(local_ip)
            assert result.status == STATUS_PRIVATE

    def test_invalid_ip_returns_unknown(self):
        service = IPReputationService()
        for bad_ip in ["not-an-ip", "999.999.999.999", "", "192.168.1"]:
            result = service.get_ip_reputation(bad_ip)
            assert result.status == STATUS_UNKNOWN

    def test_caching_reuses_successful_result(self):
        mock_provider = MagicMock()
        mock_provider.provider_name = "MockProvider"
        mock_provider.check_ip.return_value = IPReputationResult(
            ip_address="118.25.6.39",
            status=STATUS_KNOWN_MALICIOUS,
            abuse_confidence_score=90,
            provider="MockProvider"
        )

        service = IPReputationService(provider=mock_provider, cache_ttl_seconds=300)

        # First call hits provider
        res1 = service.get_ip_reputation("118.25.6.39")
        assert res1.status == STATUS_KNOWN_MALICIOUS
        assert mock_provider.check_ip.call_count == 1

        # Second call hits cache
        res2 = service.get_ip_reputation("118.25.6.39")
        assert res2.status == STATUS_KNOWN_MALICIOUS
        assert mock_provider.check_ip.call_count == 1  # Not called again

    def test_cache_expiration(self):
        mock_provider = MagicMock()
        mock_provider.provider_name = "MockProvider"
        mock_provider.check_ip.return_value = IPReputationResult(
            ip_address="118.25.6.39",
            status=STATUS_CLEAN,
            abuse_confidence_score=0,
            provider="MockProvider"
        )

        service = IPReputationService(provider=mock_provider, cache_ttl_seconds=1)

        res1 = service.get_ip_reputation("118.25.6.39")
        assert res1.status == STATUS_CLEAN
        assert mock_provider.check_ip.call_count == 1

        # Artificially expire the cache entry
        with service._lock:
            cached_res, _ = service._cache["118.25.6.39"]
            service._cache["118.25.6.39"] = (cached_res, time.time() - 10)

        res2 = service.get_ip_reputation("118.25.6.39")
        assert res2.status == STATUS_CLEAN
        assert mock_provider.check_ip.call_count == 2  # Re-queried

    def test_transient_failure_not_cached(self):
        mock_provider = MagicMock()
        mock_provider.provider_name = "MockProvider"
        mock_provider.check_ip.return_value = IPReputationResult(
            ip_address="118.25.6.39",
            status=STATUS_UNKNOWN,
            provider="MockProvider"
        )

        service = IPReputationService(provider=mock_provider, cache_ttl_seconds=300)

        res1 = service.get_ip_reputation("118.25.6.39")
        assert res1.status == STATUS_UNKNOWN

        # Subsequent call should NOT be served from cache; should re-attempt
        res2 = service.get_ip_reputation("118.25.6.39")
        assert mock_provider.check_ip.call_count == 2

    def test_disabled_service_returns_unknown(self):
        mock_provider = MagicMock()
        service = IPReputationService(provider=mock_provider, enabled=False)

        res = service.get_ip_reputation("118.25.6.39")
        assert res.status == STATUS_UNKNOWN
        mock_provider.check_ip.assert_not_called()


class TestThreatIntelligenceRiskIntegration:
    """Tests risk calculation incorporating Factor 7 threat intelligence."""

    def test_malicious_ip_elevates_risk_score(self):
        config = RiskEngineConfig()
        engine = RiskEngine(config=config)

        rep = IPReputationResult(
            ip_address="118.25.6.39",
            status=STATUS_KNOWN_MALICIOUS,
            abuse_confidence_score=100,
            total_reports=50,
            provider="AbuseIPDB"
        )

        evidence = ContextEvidence(ip_address="118.25.6.39", ip_reputation=rep)
        drift = DriftResult(drift_detected=False, reason="No drift")

        assessment = engine.evaluate_risk(drift, evidence)

        # Baseline is 0, Factor 7 with 100% abuse score contributes full weight_malicious_ip (25 points)
        assert assessment.score == config.weight_malicious_ip
        assert any("Malicious IP Reputation" in k for k in assessment.factor_breakdown)
        assert any("Malicious IP" in factor for factor in assessment.triggered_factors)

    def test_suspicious_ip_contributes_moderate_risk(self):
        config = RiskEngineConfig()
        engine = RiskEngine(config=config)

        rep = IPReputationResult(
            ip_address="142.250.190.46",
            status=STATUS_SUSPICIOUS,
            abuse_confidence_score=35,
            total_reports=5,
            provider="AbuseIPDB"
        )

        evidence = ContextEvidence(ip_address="142.250.190.46", ip_reputation=rep)
        drift = DriftResult(drift_detected=False, reason="No drift")

        assessment = engine.evaluate_risk(drift, evidence)
        # Moderate risk contribution bounded by weight_suspicious_ip
        assert 5 <= assessment.score <= config.weight_suspicious_ip
        assert any("Suspicious IP Reputation" in k for k in assessment.factor_breakdown)

    def test_clean_and_unknown_ips_add_zero_risk(self):
        config = RiskEngineConfig()
        engine = RiskEngine(config=config)

        for status in [STATUS_CLEAN, STATUS_UNKNOWN, STATUS_PRIVATE]:
            rep = IPReputationResult(
                ip_address="8.8.8.8",
                status=status,
                abuse_confidence_score=0 if status == STATUS_CLEAN else None,
                provider="AbuseIPDB"
            )
            evidence = ContextEvidence(ip_address="8.8.8.8", ip_reputation=rep)
            drift = DriftResult(drift_detected=False, reason="No drift")
            assessment = engine.evaluate_risk(drift, evidence)
            assert assessment.score == 0
            assert not any("IP Reputation" in k for k in assessment.factor_breakdown)

    def test_risk_score_capped_at_100_with_all_factors(self):
        from backend.models.assurance import AssuranceLevel
        config = RiskEngineConfig()
        engine = RiskEngine(config=config)

        rep = IPReputationResult(
            ip_address="118.25.6.39",
            status=STATUS_KNOWN_MALICIOUS,
            abuse_confidence_score=100,
            provider="AbuseIPDB"
        )

        # Max out multiple factors: drift(40) + new_device(20) + location(15) + repeated_fail(10) + auth_reg(25) + malicious_ip(25) = 135
        evidence = ContextEvidence(
            is_new_device=True,
            is_location_changed=True,
            prior_failures_count=3,
            authenticator_registered=True,
            ip_reputation=rep
        )
        drift = DriftResult(
            drift_detected=True,
            reason="Assurance downgrade",
            previous_assurance=AssuranceLevel.HIGH,
            current_assurance=AssuranceLevel.LOW
        )

        assessment = engine.evaluate_risk(drift, evidence)
        assert assessment.score == 100  # Strictly capped at 100
        assert assessment.severity == RiskSeverity.CRITICAL


class TestThreatIntelligenceAlertGenerator:
    """Tests alert generation with IP reputation telemetry and priority escalation."""

    def test_malicious_ip_escalates_priority_to_high(self):
        generator = AlertGenerator()

        rep = IPReputationResult(
            ip_address="118.25.6.39",
            status=STATUS_KNOWN_MALICIOUS,
            abuse_confidence_score=85,
            total_reports=20,
            provider="AbuseIPDB"
        )

        evidence = ContextEvidence(ip_address="118.25.6.39", ip_reputation=rep)
        drift = DriftResult(drift_detected=False, reason="No drift")
        risk = RiskEngine().evaluate_risk(drift, evidence)

        base_time = datetime(2026, 10, 30, 14, 0, 0, tzinfo=timezone.utc)
        journey = [
            AuthenticationEvent(
                event_id="evt-01",
                user_id="alice",
                timestamp=base_time,
                event_type="LOGIN",
                authentication_method="password",
                outcome="SUCCESS",
                ip_address="118.25.6.39"
            )
        ]

        alert = generator.generate_alert(
            journey=journey,
            drift_result=drift,
            context_evidence=evidence,
            risk_assessment=risk
        )

        assert alert.priority == AlertPriority.HIGH_PRIORITY
        assert alert.ip_reputation is not None
        assert alert.ip_reputation.status == STATUS_KNOWN_MALICIOUS
        assert "threat intelligence from AbuseIPDB flagged IP as KNOWN_MALICIOUS" in alert.explanation


class TestThreatIntelligencePipelineE2E:
    """End-to-end pipeline test with mocked IP reputation provider."""

    def test_pipeline_populates_reputation_and_serializes(self):
        mock_provider = MagicMock()
        mock_provider.provider_name = "AbuseIPDB"
        mock_provider.check_ip.return_value = IPReputationResult(
            ip_address="118.25.6.39",
            status=STATUS_KNOWN_MALICIOUS,
            abuse_confidence_score=92,
            total_reports=45,
            provider="AbuseIPDB",
            last_reported_at="2026-10-30T10:00:00Z"
        )
        service = IPReputationService(provider=mock_provider)
        pipeline = AuthDriftPipeline(reputation_service=service)

        raw_events = [
            {
                "id": "e-public-1",
                "time": 1793368800000,
                "type": "LOGIN",
                "realmId": "authdrift",
                "clientId": "authdrift-app",
                "userId": "usr-public-test",
                "sessionId": "sess-public-001",
                "ipAddress": "118.25.6.39",
                "details": {
                    "username": "public_user",
                    "auth_method": "password",
                    "device_id": "corporate-macbook-01",
                    "location": "Bangalore, IN"
                }
            }
        ]

        result = pipeline.process_raw_events(raw_events, provider="keycloak")
        assert len(result.alerts) == 1
        alert_obj = result.alerts[0]

        assert alert_obj.ip_reputation is not None
        assert alert_obj.ip_reputation.status == STATUS_KNOWN_MALICIOUS
        assert alert_obj.ip_reputation.abuse_confidence_score == 92
        assert alert_obj.ip_reputation.provider == "AbuseIPDB"
        assert alert_obj.priority == AlertPriority.HIGH_PRIORITY

        # Verify serialization
        serialized = result.to_dict()
        assert len(serialized["alerts"]) == 1
        ser_alert = serialized["alerts"][0]
        assert "ip_reputation" in ser_alert
        assert ser_alert["ip_reputation"]["status"] == STATUS_KNOWN_MALICIOUS
        assert ser_alert["ip_reputation"]["abuse_confidence_score"] == 92
