"""
Regression tests: primary location / observed location / status / IP address must
flow from raw provider logs through normalization, profiling, context analysis,
the API payload, and the dashboard renderer.
"""
import json
import shutil
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from backend.api import app
from backend.correlation.location_profiler import LocationProfiler
from backend.models.event import AuthenticationEvent
from backend.normalization.keycloak import KeycloakEventNormalizer
from backend.normalization.okta import OktaEventNormalizer
from backend.pipeline.pipeline import AuthDriftPipeline

BASE = datetime(2026, 10, 1, 9, 0, tzinfo=timezone.utc)


def kc(event_id, day, user, location, ip, outcome="LOGIN"):
    """Raw Keycloak event, one per day so every login is its own journey."""
    ts = int((BASE + timedelta(days=day)).timestamp() * 1000)
    details = {"username": user, "auth_method": "password"}
    if location is not None:
        details["location"] = location
    return {
        "id": event_id, "time": ts, "type": outcome, "userId": user,
        "sessionId": f"sess-{event_id}", "ipAddress": ip, "details": details,
    }


def alert_for(result, user, index=-1):
    alerts = [a for a in result["alerts"] if a["user_id"] == user]
    return alerts[index]["context_evidence"]


def bengaluru_then_berlin(user="alice"):
    return [
        kc(f"{user}-1", 0, user, "Bengaluru, India", "10.0.0.1"),
        kc(f"{user}-2", 1, user, "Bengaluru, India", "10.0.0.1"),
        kc(f"{user}-3", 2, user, "Bengaluru, India", "10.0.0.2"),
        kc(f"{user}-4", 3, user, "Berlin, Germany", "203.0.113.20"),
    ]


class TestPrimaryAndObservedLocation:
    def test_bengaluru_history_sets_primary(self):
        result = AuthDriftPipeline().process_raw_events(bengaluru_then_berlin()[:3]).to_dict()
        ctx = alert_for(result, "alice")
        assert ctx["primary_location"] == "Bengaluru, India"
        assert ctx["location"] == "Bengaluru, India"
        assert ctx["location_status"] == "KNOWN"

    def test_later_berlin_login_is_new_with_bengaluru_primary(self):
        result = AuthDriftPipeline().process_raw_events(bengaluru_then_berlin()).to_dict()
        ctx = alert_for(result, "alice")
        assert ctx["primary_location"] == "Bengaluru, India"
        assert ctx["location"] == "Berlin, Germany"
        assert ctx["location_status"] == "NEW"
        assert ctx["ip_address"] == "203.0.113.20"
        assert ctx["is_location_changed"] is True

    def test_current_login_does_not_contaminate_own_baseline(self):
        # Before the fix the Berlin login was part of the baseline and came back KNOWN.
        result = AuthDriftPipeline().process_raw_events(bengaluru_then_berlin()).to_dict()
        assert alert_for(result, "alice")["location_status"] != "KNOWN"

    def test_two_berlin_logins_make_second_known_only_after_history(self):
        raw = bengaluru_then_berlin() + [kc("alice-5", 4, "alice", "Berlin, Germany", "203.0.113.20")]
        result = AuthDriftPipeline().process_raw_events(raw).to_dict()
        assert alert_for(result, "alice", -2)["location_status"] == "NEW"
        last = alert_for(result, "alice", -1)
        assert last["location_status"] == "KNOWN"
        assert last["primary_location"] == "Bengaluru, India"

    def test_failed_logins_do_not_build_baseline(self):
        raw = [kc(f"f{i}", i, "alice", "Bengaluru, India", "10.0.0.1", outcome="LOGIN_ERROR") for i in range(3)]
        raw.append(kc("ok", 5, "alice", "Berlin, Germany", "203.0.113.20"))
        ctx = alert_for(AuthDriftPipeline().process_raw_events(raw).to_dict(), "alice")
        assert ctx["primary_location"] is None
        assert ctx["location_status"] == "UNKNOWN"

    def test_insufficient_history_is_unknown_without_guessing_primary(self):
        raw = [kc("a1", 0, "alice", "Bengaluru, India", "10.0.0.1"),
               kc("a2", 1, "alice", "Berlin, Germany", "203.0.113.20")]
        ctx = alert_for(AuthDriftPipeline().process_raw_events(raw).to_dict(), "alice")
        assert ctx["primary_location"] is None
        assert ctx["location_status"] == "UNKNOWN"
        assert ctx["location"] == "Berlin, Germany"

    def test_users_are_isolated(self):
        raw = bengaluru_then_berlin("alice") + [kc("bob-1", 3, "bob", "Berlin, Germany", "198.51.100.7")]
        result = AuthDriftPipeline().process_raw_events(raw).to_dict()
        bob = alert_for(result, "bob")
        assert bob["primary_location"] is None
        assert bob["location_status"] == "UNKNOWN"
        assert alert_for(result, "alice")["primary_location"] == "Bengaluru, India"

    def test_snapshot_ignores_other_users_and_future_events(self):
        profiler = LocationProfiler(min_successful_observations=2)
        ev = lambda i, u, d, loc: AuthenticationEvent(
            event_id=i, user_id=u, timestamp=BASE + timedelta(days=d), event_type="LOGIN",
            authentication_method="password", outcome="SUCCESS", location=loc)
        events = [ev("1", "a", 0, "Bengaluru, India"), ev("2", "a", 1, "Bengaluru, India"),
                  ev("3", "b", 1, "Berlin, Germany"), ev("4", "a", 5, "Paris, France")]
        snap = profiler.snapshot_before(events, "a", before=BASE + timedelta(days=3))
        assert snap.get_profile("b") is None
        assert snap.get_profile("a").known_locations == {"Bengaluru, India"}

    def test_rebuilding_profiles_clears_stale_profiles(self):
        profiler = LocationProfiler(min_successful_observations=1)
        old = AuthenticationEvent(event_id="1", user_id="gone", timestamp=BASE, event_type="LOGIN",
                                  authentication_method="password", outcome="SUCCESS", location="Oslo, Norway")
        new = AuthenticationEvent(event_id="2", user_id="here", timestamp=BASE, event_type="LOGIN",
                                  authentication_method="password", outcome="SUCCESS", location="Lima, Peru")
        profiler.build_profiles([old])
        profiler.build_profiles([new])
        assert profiler.get_profile("gone") is None
        assert profiler.get_profile("here").primary_location == "Lima, Peru"


class TestIpAndMissingData:
    def test_ip_is_never_used_as_location_keycloak(self):
        n = KeycloakEventNormalizer()
        no_loc = n.normalize_single(kc("x", 0, "u", None, "203.0.113.20"))
        assert no_loc.location is None and no_loc.ip_address == "203.0.113.20"
        ip_as_loc = n.normalize_single(kc("y", 0, "u", "203.0.113.20", "203.0.113.20"))
        assert ip_as_loc.location is None
        v6 = n.normalize_single(kc("z", 0, "u", "2001:db8::1", "2001:db8::1"))
        assert v6.location is None

    def test_ip_is_never_used_as_location_okta(self):
        raw = {"uuid": "o1", "published": "2026-10-30T14:10:00.000Z",
               "eventType": "user.authentication.authenticate", "outcome": {"result": "SUCCESS"},
               "actor": {"alternateId": "a@x.com"}, "client": {"ipAddress": "203.0.113.9"}}
        ev = OktaEventNormalizer().normalize_single(raw)
        assert ev.location is None and ev.ip_address == "203.0.113.9"

    def test_okta_city_country_composition_and_partial_data(self):
        def okta(geo):
            return OktaEventNormalizer().normalize_single({
                "uuid": "o", "published": "2026-10-30T14:10:00.000Z",
                "eventType": "user.authentication.authenticate", "outcome": {"result": "SUCCESS"},
                "actor": {"alternateId": "a@x.com"}, "client": {"geographicalContext": geo}})
        assert okta({"city": "Berlin", "country": "Germany"}).location == "Berlin, Germany"
        assert okta({"country": "Germany"}).location == "Germany"
        assert okta({"city": "  ", "country": None}).location is None
        assert okta({"city": {"x": 1}, "country": ["y"]}).location is None
        assert okta("not-a-dict").location is None

    def test_keycloak_city_and_country_fields(self):
        raw = kc("k", 0, "u", None, "10.0.0.1")
        raw["details"].update({"city": "Berlin", "country": "Germany"})
        assert KeycloakEventNormalizer().normalize_single(raw).location == "Berlin, Germany"

    def test_missing_location_does_not_crash_or_fabricate(self):
        raw = [kc("m1", 0, "alice", None, "10.0.0.1"), kc("m2", 1, "alice", None, "10.0.0.1"),
               kc("m3", 2, "alice", None, "10.0.0.1")]
        result = AuthDriftPipeline().process_raw_events(raw).to_dict()
        ctx = alert_for(result, "alice")
        assert ctx["location"] is None and ctx["primary_location"] is None
        assert ctx["location_status"] == "UNKNOWN"
        assert ctx["ip_address"] == "10.0.0.1"


class TestApiPayload:
    def setup_method(self):
        self.client = TestClient(app)

    def ingest(self, events, provider="keycloak"):
        res = self.client.post("/api/pipeline/run", json={"provider": provider, "events": events})
        assert res.status_code == 200, res.text
        return res.json()

    def test_run_response_and_get_endpoints_include_location_fields(self):
        data = self.ingest(bengaluru_then_berlin())
        berlin_journey = [j for j in data["journeys"] if j["user_id"] == "alice"][-1]
        assert berlin_journey["location_context"] == {
            "primary_location": "Bengaluru, India", "location": "Berlin, Germany",
            "location_status": "NEW", "ip_address": "203.0.113.20"}
        # journey links to its own alert (not just the first alert of that user)
        linked = [a for a in data["alerts"] if a["alert_id"] == berlin_journey["alert_id"]][0]
        assert linked["context_evidence"]["location_status"] == "NEW"

        journeys = self.client.get("/api/journeys").json()["journeys"]
        alerts = self.client.get("/api/alerts").json()["alerts"]
        assert all("location_context" in j and "alert_id" in j for j in journeys)
        for a in alerts:
            for key in ("primary_location", "location", "location_status", "ip_address"):
                assert key in a["context_evidence"]

    def test_second_ingestion_replaces_values_instead_of_going_stale(self):
        self.ingest(bengaluru_then_berlin())
        data = self.ingest([kc("solo", 0, "alice", "Paris, France", "198.51.100.1")])
        ctx = data["alerts"][0]["context_evidence"]
        assert ctx["primary_location"] is None
        assert ctx["location"] == "Paris, France"
        assert ctx["location_status"] == "UNKNOWN"
        assert len(data["journeys"]) == 1


NODE = shutil.which("node")
VIEW_JS = Path(__file__).resolve().parent.parent / "dashboard" / "location_view.js"


def render(ctx):
    script = ("const v=require(process.argv[1]);"
              "process.stdout.write(v.buildLocationFieldsHtml(JSON.parse(process.argv[2])));")
    out = subprocess.run([NODE, "-e", script, str(VIEW_JS), json.dumps(ctx)],
                         capture_output=True, text=True, check=True)
    return out.stdout


@pytest.mark.skipif(NODE is None, reason="node not installed")
class TestDashboardLocationView:
    """Runs the dashboard's real rendering module under Node (string output, no browser)."""

    def test_renders_all_four_fields(self):
        html = render({"primary_location": "Bengaluru, India", "location": "Berlin, Germany",
                       "location_status": "NEW", "ip_address": "203.0.113.20"})
        for label in ("Primary Location", "Observed Location", "Location Status", "IP Address"):
            assert label in html
        assert 'data-field="primary_location">Bengaluru, India<' in html
        assert 'data-field="location">Berlin, Germany<' in html
        assert "loc-status-new" in html and ">NEW<" in html
        assert "203.0.113.20" in html

    def test_missing_values_show_not_available_and_unknown_status(self):
        html = render({})
        assert html.count("Not available") == 3
        assert "loc-status-unknown" in html and ">UNKNOWN<" in html

    def test_invalid_status_is_not_trusted(self):
        assert "loc-status-unknown" in render({"location_status": "WHATEVER"})

    def test_values_from_logs_are_html_escaped(self):
        html = render({"location": "<img src=x onerror=alert(1)>"})
        assert "<img" not in html and "&lt;img" in html
