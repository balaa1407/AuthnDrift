"""
AuthDrift: Core Pipeline Coordinator.
Directly integrates:
1. Provider Normalization (Keycloak / Okta / Vendor-neutral)
2. Event Deduplication
3. Authentication Journey Reconstruction
4. Balaa's AuthDriftEngine (Detection, Correlation, Risk Scoring, Alerts)
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set
from backend.engine import AuthDriftEngine
from backend.models.event import AuthenticationEvent, AuthenticationJourney
from backend.models.detection import SecurityAlert
from backend.normalization.base import BaseEventNormalizer
from backend.normalization.keycloak import KeycloakEventNormalizer
from backend.normalization.okta import OktaEventNormalizer
from backend.normalization.deduplicator import EventDeduplicator
from backend.journey.reconstructor import JourneyReconstructor


@dataclass
class PipelineExecutionResult:
    """
    Standardized payload summarizing the pipeline run for API and Dashboard display.
    """
    total_raw_events: int
    normalized_events: List[AuthenticationEvent]
    journeys: List[AuthenticationJourney]
    alerts: List[SecurityAlert]
    metrics: Dict[str, Any]
    provider: str
    execution_time: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> Dict[str, Any]:
        """Serializes the pipeline result to JSON-compatible dictionary."""
        return {
            "total_raw_events": self.total_raw_events,
            "provider": self.provider,
            "metrics": self.metrics,
            "events": [
                {
                    "event_id": e.event_id,
                    "user_id": e.user_id,
                    "timestamp": e.timestamp.isoformat() if e.timestamp else None,
                    "event_type": e.event_type,
                    "authentication_method": e.authentication_method,
                    "outcome": e.outcome,
                    "device_id": e.device_id,
                    "location": e.location,
                    "authenticator_id": e.authenticator_id,
                    "session_id": e.session_id,
                    "source_provider": e.source_provider
                }
                for e in self.normalized_events
            ],
            "journeys": [
                {
                    "user_id": j.user_id,
                    "session_id": j.session_id,
                    "event_count": len(j.events),
                    "start_time": j.events[0].timestamp.isoformat() if j.events else None,
                    "end_time": j.events[-1].timestamp.isoformat() if j.events else None,
                    "events": [
                        {
                            "event_id": e.event_id,
                            "user_id": e.user_id,
                            "timestamp": e.timestamp.isoformat() if e.timestamp else None,
                            "event_type": e.event_type,
                            "authentication_method": e.authentication_method,
                            "outcome": e.outcome,
                            "device_id": e.device_id,
                            "location": e.location,
                            "authenticator_id": e.authenticator_id,
                            "session_id": e.session_id
                        }
                        for e in j.events
                    ]
                }
                for j in self.journeys
            ],
            "alerts": [
                {
                    "alert_id": a.alert_id,
                    "user_id": a.user_id,
                    "timestamp": a.timestamp.isoformat() if a.timestamp else None,
                    "drift_detected": a.drift_detected,
                    "is_actionable": a.is_actionable,
                    "methods_involved": a.methods_involved,
                    "explanation": a.explanation,
                    "session_id": a.session_id,
                    "drift_result": {
                        "drift_detected": a.drift_result.drift_detected,
                        "reason": a.drift_result.reason,
                        "previous_method": a.drift_result.previous_method,
                        "previous_assurance": a.drift_result.previous_assurance.name if a.drift_result.previous_assurance else None,
                        "current_method": a.drift_result.current_method,
                        "current_assurance": a.drift_result.current_assurance.name if a.drift_result.current_assurance else None,
                        "transition_type": a.drift_result.transition_type
                    },
                    "context_evidence": {
                        "is_new_device": a.context_evidence.is_new_device,
                        "device_id": a.context_evidence.device_id,
                        "is_location_changed": a.context_evidence.is_location_changed,
                        "location": a.context_evidence.location,
                        "authenticator_registered": a.context_evidence.authenticator_registered,
                        "authenticator_id": a.context_evidence.authenticator_id,
                        "prior_failures_count": a.context_evidence.prior_failures_count,
                        "evidence_notes": a.context_evidence.evidence_notes
                    },
                    "risk_assessment": {
                        "score": a.risk_assessment.score,
                        "severity": a.risk_assessment.severity.value,
                        "triggered_factors": a.risk_assessment.triggered_factors,
                        "factor_breakdown": a.risk_assessment.factor_breakdown,
                        "rationale": a.risk_assessment.rationale
                    }
                }
                for a in self.alerts
            ]
        }


class AuthDriftPipeline:
    """
    Coordinates the entire AuthDrift processing pipeline.
    """

    def __init__(
        self,
        engine: Optional[AuthDriftEngine] = None,
        reconstructor: Optional[JourneyReconstructor] = None,
        deduplicator: Optional[EventDeduplicator] = None
    ):
        self.engine = engine or AuthDriftEngine()
        self.reconstructor = reconstructor or JourneyReconstructor()
        self.deduplicator = deduplicator or EventDeduplicator()

        self._normalizers: Dict[str, BaseEventNormalizer] = {
            "keycloak": KeycloakEventNormalizer(),
            "okta": OktaEventNormalizer()
        }

        # Baseline contextual baseline profiles for evaluation
        self.known_devices: Set[str] = {"corporate-macbook-01", "pixel-9-pro", "laptop-01", "MacBookPro18,1"}
        self.known_locations: Set[str] = {"Bangalore, IN", "San Francisco, United States", "127.0.0.1"}
        self.known_authenticators: Set[str] = {"corporate-yubikey-01", "key-01"}

    def register_normalizer(self, provider_name: str, normalizer: BaseEventNormalizer) -> None:
        """Allows registering custom or third-party identity provider normalizers."""
        self._normalizers[provider_name.lower().strip()] = normalizer

    def get_normalizer(self, provider_name: str) -> BaseEventNormalizer:
        """Retrieves normalizer for a provider, defaulting to Keycloak."""
        return self._normalizers.get(provider_name.lower().strip(), self._normalizers["keycloak"])

    def process_raw_events(
        self,
        raw_events: List[Dict[str, Any]],
        provider: str = "keycloak",
        deduplicate: bool = True
    ) -> PipelineExecutionResult:
        """
        Executes end-to-end pipeline:
        1. Normalization from raw provider format
        2. Deduplication
        3. Journey Reconstruction
        4. AuthDriftEngine Evaluation
        5. Metric Compilation
        """
        total_raw = len(raw_events)
        normalizer = self.get_normalizer(provider)

        # 1. Normalization
        normalized = normalizer.normalize_batch(raw_events)

        # 2. Deduplication
        if deduplicate:
            events_to_process = self.deduplicator.filter_duplicates(normalized)
        else:
            events_to_process = normalized

        # 3. Journey Reconstruction
        journeys = self.reconstructor.reconstruct_journeys(events_to_process)

        # 4. AuthDriftEngine Detection Evaluation
        alerts: List[SecurityAlert] = []
        for journey in journeys:
            alert = self.engine.evaluate_journey(
                journey=journey.events,
                known_devices=self.known_devices,
                known_locations=self.known_locations,
                known_authenticators=self.known_authenticators,
                session_id=journey.session_id
            )
            alerts.append(alert)

        # 5. Metrics calculation
        severity_counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
        drift_count = 0
        actionable_count = 0

        for a in alerts:
            severity_counts[a.risk_assessment.severity.value] += 1
            if a.drift_detected:
                drift_count += 1
            if a.is_actionable:
                actionable_count += 1

        metrics = {
            "total_raw_events": total_raw,
            "processed_events": len(events_to_process),
            "reconstructed_journeys": len(journeys),
            "detected_drift_alerts": drift_count,
            "actionable_alerts": actionable_count,
            "severity_distribution": severity_counts,
            "drift_rate_percentage": round((drift_count / len(journeys) * 100) if journeys else 0, 1)
        }

        return PipelineExecutionResult(
            total_raw_events=total_raw,
            normalized_events=events_to_process,
            journeys=journeys,
            alerts=alerts,
            metrics=metrics,
            provider=provider
        )

