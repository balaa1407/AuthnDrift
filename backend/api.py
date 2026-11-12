"""
AuthDrift: Managed FastAPI Web API & Background Application Service.
Serves the REST API for overview metrics, reconstructed journeys, security alerts,
and IP threat intelligence with structured logging, lifespan lifecycle management,
and non-blocking asynchronous event handling.
"""

from contextlib import asynccontextmanager
from datetime import datetime, timezone
import json
import logging
import os
import sys
from typing import Any, Dict, List, Optional
import anyio
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from backend.pipeline.pipeline import AuthDriftPipeline, PipelineExecutionResult
from backend.threat_intelligence.reputation_service import IPReputationService
from keycloak.generate_keycloak_fixtures import generate_keycloak_fixtures, generate_okta_fixtures

# Structured Logging Configuration
LOG_LEVEL_STR = os.getenv("AUTH_DRIFT_LOG_LEVEL", "INFO").upper()
log_level = getattr(logging, LOG_LEVEL_STR, logging.INFO)

logging.basicConfig(
    level=log_level,
    format="%(asctime)s [%(levelname)s] [%(name)s]: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[logging.StreamHandler(sys.stdout)],
)

logger = logging.getLogger("authdrift.api")

# Application Start Time for Health Checks
SERVICE_START_TIME = datetime.now(timezone.utc)

# Global pipeline instance
reputation_service = IPReputationService()
pipeline = AuthDriftPipeline(reputation_service=reputation_service)
current_result: Optional[PipelineExecutionResult] = None


def initialize_default_data() -> None:
    """Pre-populates the pipeline with standard Keycloak scenarios on startup."""
    global current_result
    try:
        raw_events = generate_keycloak_fixtures()
        current_result = pipeline.process_raw_events(raw_events, provider="keycloak")
        logger.info(
            "Default scenario fixtures loaded: %s raw events, %s journeys, %s alerts generated.",
            len(raw_events),
            len(current_result.journeys),
            len(current_result.alerts),
        )
    except Exception as e:
        logger.error("Failed to load initial fixtures: %s", str(e), exc_info=True)


# Initialize default dataset on module import for immediate readiness & test client compatibility
initialize_default_data()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    FastAPI lifespan manager handling application startup and graceful shutdown.
    """
    logger.info("Starting AuthDrift Security Intelligence Engine (v1.1.0)...")
    logger.info("Threat intelligence provider: %s (enabled: %s)", reputation_service.provider.provider_name, reputation_service.enabled)
    if current_result is None:
        initialize_default_data()
    yield
    logger.info("AuthDrift application shutting down. Purging transient caches...")
    reputation_service.clear_cache()
    logger.info("AuthDrift application shutdown complete.")


app = FastAPI(
    title="AuthDrift Security Intelligence Engine",
    description="Authentication Assurance Drift Detection, Journey Reconstruction, and IP Threat Intelligence API",
    version="1.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class RunPipelineRequest(BaseModel):
    provider: str = "keycloak"
    events: List[Dict[str, Any]]
    deduplicate: bool = True


@app.get("/api/health")
@app.get("/health")
def get_health():
    """
    Operational healthcheck endpoint for Docker containers and monitoring probes.
    """
    now = datetime.now(timezone.utc)
    uptime_seconds = (now - SERVICE_START_TIME).total_seconds()
    return {
        "status": "HEALTHY",
        "service": "AuthDrift",
        "version": "1.1.0",
        "uptime_seconds": round(uptime_seconds, 1),
        "threat_intelligence": {
            "provider": reputation_service.provider.provider_name,
            "configured": getattr(reputation_service.provider, "is_configured", False),
            "enabled": reputation_service.enabled,
            "cached_ips_count": reputation_service.cache_size,
        },
        "pipeline_ready": current_result is not None,
    }


@app.get("/api/overview")
def get_overview():
    """Returns summary metrics and risk distribution for the current dataset."""
    if not current_result:
        raise HTTPException(status_code=404, detail="No pipeline data available.")
    return {
        "provider": current_result.provider,
        "metrics": current_result.metrics,
        "total_raw_events": current_result.total_raw_events,
        "execution_time": current_result.execution_time.isoformat(),
    }


@app.get("/api/journeys")
def get_journeys(
    user_id: Optional[str] = Query(None, description="Filter journeys by user ID"),
    outcome: Optional[str] = Query(None, description="Filter by event outcome (SUCCESS/FAILURE)")
):
    """Returns reconstructed authentication journeys with optional filtering."""
    if not current_result:
        return {"journeys": []}

    payload = current_result.to_dict()["journeys"]

    if user_id:
        payload = [j for j in payload if user_id.lower() in j["user_id"].lower()]

    if outcome:
        target_outcome = outcome.upper()
        payload = [
            j for j in payload
            if any(e["outcome"] == target_outcome for e in j["events"])
        ]

    return {"journeys": payload, "count": len(payload)}


@app.get("/api/alerts")
def get_alerts(
    user_id: Optional[str] = Query(None, description="Filter alerts by user ID"),
    severity: Optional[str] = Query(None, description="Filter by risk severity (LOW/MEDIUM/HIGH/CRITICAL)"),
    drift_only: bool = Query(False, description="Filter for drift_detected == True")
):
    """Returns security alerts generated by AuthDriftEngine."""
    if not current_result:
        return {"alerts": []}

    payload = current_result.to_dict()["alerts"]

    if user_id:
        payload = [a for a in payload if user_id.lower() in a["user_id"].lower()]

    if severity:
        target_sev = severity.upper()
        payload = [a for a in payload if a["risk_assessment"]["severity"] == target_sev]

    if drift_only:
        payload = [a for a in payload if a["drift_detected"] is True]

    return {"alerts": payload, "count": len(payload)}


@app.post("/api/pipeline/run")
async def run_pipeline(request: RunPipelineRequest):
    """
    Ingests arbitrary raw events (Keycloak or Okta format) and executes the detection pipeline
    in a worker thread to prevent blocking the async event loop during threat intelligence lookups.
    """
    global current_result
    try:
        result = await anyio.to_thread.run_sync(
            pipeline.process_raw_events,
            request.events,
            request.provider,
            request.deduplicate,
        )
        current_result = result
        return current_result.to_dict()
    except Exception as e:
        logger.error("Pipeline execution error: %s", str(e), exc_info=True)
        raise HTTPException(status_code=400, detail=f"Pipeline execution failed: {str(e)}")


@app.get("/api/threat-intel/lookup")
async def lookup_ip_threat_intel(
    ip: str = Query(..., description="IPv4 or IPv6 address to evaluate against threat intelligence")
):
    """
    Direct threat intelligence lookup endpoint for ad-hoc IP verification.
    """
    try:
        rep_result = await anyio.to_thread.run_sync(
            reputation_service.get_ip_reputation,
            ip
        )
        return rep_result.to_dict()
    except Exception as e:
        logger.error("Threat intelligence lookup failed for IP %s: %s", ip, str(e))
        raise HTTPException(status_code=500, detail=f"Lookup failed: {str(e)}")


@app.get("/api/scenarios")
def list_scenarios():
    """Lists available controlled test scenarios."""
    return {
        "scenarios": [
            {"id": "all", "name": "All Scenarios (TC01-TC11)", "provider": "keycloak"},
            {"id": "client_recovery", "name": "Benchmark Case Study: Verified Client Recovery (Known Hardware & Subnet ➔ No Drift)", "provider": "keycloak"},
            {"id": "adversarial_downgrade", "name": "Benchmark Case Study: Adversarial Assurance Downgrade (Unfamiliar Endpoint ➔ Drift Alert)", "provider": "keycloak"},
            {"id": "research_dataset", "name": "Research Benchmark: 145 Enterprise Journeys (5 Cohorts: Lyastani, Wiefling, LANL, Freeman, Thomas)", "provider": "keycloak"},
            {"id": "tc01", "name": "TC01: Known Device Passkey Success (Alice)", "provider": "keycloak"},
            {"id": "tc02", "name": "TC02: Benign Recovery on Known Device (Bob)", "provider": "keycloak"},
            {"id": "tc03", "name": "TC03: Fallback + New Device Context (Carol)", "provider": "keycloak"},
            {"id": "tc04", "name": "TC04: Repeated Failed Logins (Dave)", "provider": "keycloak"},
            {"id": "tc05", "name": "TC05: Downgrade + Rogue Authenticator Registration (Eve)", "provider": "keycloak"},
            {"id": "tc06", "name": "TC06: Legitimate Recovery / Migration (Frank)", "provider": "keycloak"},
            {"id": "tc10", "name": "TC10: Threat Intelligence: Malicious Public IP (Victor)", "provider": "keycloak"},
            {"id": "tc11", "name": "TC11: Threat Intelligence: Clean Public IP (Wendy)", "provider": "keycloak"},
            {"id": "okta", "name": "Vendor-Neutral Ingestion: Okta System Log (Alex)", "provider": "okta"}
        ]
    }


@app.post("/api/scenarios/{scenario_id}/load")
async def load_scenario(scenario_id: str):
    """Loads a specific scenario fixture into the live pipeline."""
    global current_result
    all_events = generate_keycloak_fixtures()

    research_events = None
    if scenario_id.lower() == "research_dataset":
        from backend.synthetic_data.research_dataset_generator import (
            generate_research_synthetic_dataset,
            KNOWN_BENCHMARK_DEVICES
        )
        data = generate_research_synthetic_dataset()
        research_events = data["events"]
        pipeline.known_devices.update(KNOWN_BENCHMARK_DEVICES)

    bob_events = [e for e in all_events if "bob" in e.get("details", {}).get("username", "")]
    carol_events = [e for e in all_events if "carol" in e.get("details", {}).get("username", "")]

    scenario_map = {
        "all": (all_events, "keycloak"),
        "client_recovery": (bob_events, "keycloak"),
        "sir_recovery": (bob_events, "keycloak"),  # Backward compatibility alias
        "adversarial_downgrade": (carol_events, "keycloak"),
        "sir_attack": (carol_events, "keycloak"),  # Backward compatibility alias
        "research_dataset": (research_events if research_events else [], "keycloak"),
        "tc01": ([e for e in all_events if "alice" in e.get("details", {}).get("username", "")], "keycloak"),
        "tc02": ([e for e in all_events if "bob" in e.get("details", {}).get("username", "")], "keycloak"),
        "tc03": ([e for e in all_events if "carol" in e.get("details", {}).get("username", "")], "keycloak"),
        "tc04": ([e for e in all_events if "dave" in e.get("details", {}).get("username", "")], "keycloak"),
        "tc05": ([e for e in all_events if "eve" in e.get("details", {}).get("username", "")], "keycloak"),
        "tc06": ([e for e in all_events if "frank" in e.get("details", {}).get("username", "")], "keycloak"),
        "tc10": ([e for e in all_events if "victor" in e.get("details", {}).get("username", "")], "keycloak"),
        "tc11": ([e for e in all_events if "wendy" in e.get("details", {}).get("username", "")], "keycloak"),
        "okta": (generate_okta_fixtures(), "okta")
    }

    target = scenario_map.get(scenario_id.lower())
    if not target:
        raise HTTPException(status_code=404, detail=f"Scenario '{scenario_id}' not found.")

    events, provider = target
    pipeline.deduplicator.reset()
    current_result = await anyio.to_thread.run_sync(
        pipeline.process_raw_events,
        events,
        provider,
    )
    return current_result.to_dict()


# Serve static dashboard
dashboard_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "dashboard")
if os.path.isdir(dashboard_dir):
    app.mount("/static", StaticFiles(directory=dashboard_dir), name="static")

    @app.get("/")
    def serve_dashboard():
        index_path = os.path.join(dashboard_dir, "index.html")
        if os.path.exists(index_path):
            return FileResponse(index_path)
        return {"status": "AuthDrift API online. Dashboard file not found at " + index_path}
