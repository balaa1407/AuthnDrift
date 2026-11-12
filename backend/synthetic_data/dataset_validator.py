"""
AuthDrift: Synthetic Dataset Validation Suite.
Fulfills Person 1 Task 1 Step 4: Validates event schema, timestamp integrity,
chronological consistency, single-user isolation, ground-truth alignment,
and scenario category distributions.
"""

from dataclasses import dataclass, field
from datetime import datetime
import json
import os
from typing import Any, Dict, List, Optional, Set


@dataclass
class ValidationReport:
    """Detailed report summarizing dataset validation findings."""
    is_valid: bool
    total_events: int
    total_journeys: int
    category_counts: Dict[str, int] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    def summary(self) -> str:
        status = "PASSED" if self.is_valid else "FAILED"
        return (
            f"Dataset Validation {status}: {self.total_events} events across {self.total_journeys} journeys.\n"
            f"Category Distribution: {self.category_counts}\n"
            f"Errors: {len(self.errors)}, Warnings: {len(self.warnings)}"
        )


class DatasetValidator:
    """
    Validates synthetic authentication datasets against production invariants.
    """

    REQUIRED_RAW_FIELDS = {"id", "time", "type", "userId", "details"}
    REQUIRED_DETAIL_FIELDS = {"username", "auth_method"}

    VALID_EVENT_TYPES = {
        "LOGIN",
        "LOGIN_ERROR",
        "REGISTER",
        "REGISTER_AUTHENTICATOR",
        "UPDATE_CREDENTIAL",
        "DELETE_CREDENTIAL",
        "REFRESH_TOKEN",
        "LOGOUT"
    }

    def validate_file(self, file_path: str) -> ValidationReport:
        """Loads and validates a synthetic dataset JSON file from disk."""
        if not os.path.exists(file_path):
            return ValidationReport(
                is_valid=False,
                total_events=0,
                total_journeys=0,
                errors=[f"File not found: {file_path}"]
            )
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            return self.validate_dataset(data)
        except Exception as e:
            return ValidationReport(
                is_valid=False,
                total_events=0,
                total_journeys=0,
                errors=[f"Failed to parse JSON file {file_path}: {str(e)}"]
            )

    def validate_dataset(self, dataset: Dict[str, Any]) -> ValidationReport:
        errors: List[str] = []
        warnings: List[str] = []

        if not isinstance(dataset, dict):
            return ValidationReport(is_valid=False, total_events=0, total_journeys=0, errors=["Dataset root is not a dictionary."])

        if "metadata" not in dataset:
            errors.append("Missing required root key: metadata")
        if "ground_truth" not in dataset:
            errors.append("Missing required root key: ground_truth")
        if "events" not in dataset:
            errors.append("Missing required root key: events")

        metadata = dataset.get("metadata", {})
        ground_truth = dataset.get("ground_truth", {})
        events = dataset.get("events", [])

        if not isinstance(events, list) or not events:
            errors.append("Dataset 'events' field is missing, empty, or not a list.")
            return ValidationReport(is_valid=False, total_events=0, total_journeys=0, errors=errors)

        # 1. Validate Metadata & Citations
        papers = metadata.get("research_papers", [])
        if not papers:
            warnings.append("Metadata 'research_papers' is empty.")
        else:
            citations_text = " ".join([p.get("citation", "") for p in papers])
            for expected in ["Lyastani", "Wiefling", "Kent", "Bonneau", "Alaca", "Freeman", "Thomas"]:
                if expected not in citations_text:
                    warnings.append(f"Missing recommended research paper citation: {expected}")

        # 2. Validate Events Schema & Sequencing
        seen_event_ids: Set[str] = set()
        user_events: Dict[str, List[Dict[str, Any]]] = {}

        for idx, ev in enumerate(events):
            if not isinstance(ev, dict):
                errors.append(f"Event at index {idx} is not a dictionary.")
                continue

            # Check required fields
            missing = self.REQUIRED_RAW_FIELDS - set(ev.keys())
            if missing:
                errors.append(f"Event at index {idx} ({ev.get('id', 'unknown')}) missing required fields: {missing}")

            # Deduplication
            eid = ev.get("id")
            if eid in seen_event_ids:
                errors.append(f"Duplicate event_id detected: '{eid}' at index {idx}.")
            elif eid:
                seen_event_ids.add(eid)

            # Timestamp validity
            t = ev.get("time")
            if not isinstance(t, (int, float)) or t <= 0:
                errors.append(f"Event '{eid}' has invalid epoch timestamp: {t}")

            # Event type validity
            etype = str(ev.get("type") or "").strip().upper()
            if etype not in self.VALID_EVENT_TYPES:
                warnings.append(f"Event '{eid}' has unusual event_type: '{etype}'")

            # Details dictionary
            details = ev.get("details", {})
            if not isinstance(details, dict):
                errors.append(f"Event '{eid}' 'details' is not a dictionary.")
            else:
                detail_missing = self.REQUIRED_DETAIL_FIELDS - set(details.keys())
                if detail_missing:
                    errors.append(f"Event '{eid}' details missing: {detail_missing}")

            # Group for user journey validation
            uid = ev.get("userId") or details.get("username")
            if uid:
                user_events.setdefault(uid, []).append(ev)

        # 3. Validate Chronological Ordering and Session Consistency per User
        for uid, u_evs in user_events.items():
            sorted_by_time = sorted(u_evs, key=lambda e: e.get("time", 0))
            if u_evs != sorted_by_time:
                errors.append(f"Chronological violation: User '{uid}' events are not in non-decreasing order in the dataset.")

            # Verify session consistency: within a session_id, user must remain constant
            sessions: Dict[str, Set[str]] = {}
            for ev in u_evs:
                sess_id = ev.get("sessionId")
                if sess_id:
                    sessions.setdefault(sess_id, set()).add(uid)

            for sess_id, u_set in sessions.items():
                if len(u_set) > 1:
                    errors.append(f"Cross-user session contamination: session '{sess_id}' shared by users {u_set}.")

        # 4. Validate Ground-Truth Consistency
        category_counts: Dict[str, int] = {}
        for username, gt in ground_truth.items():
            cat = gt.get("category", "UNKNOWN")
            category_counts[cat] = category_counts.get(cat, 0) + 1

            if "expected_drift" not in gt:
                errors.append(f"Ground truth for user '{username}' missing 'expected_drift'.")

            # Check matching user events exist
            matching_events = [
                e for e in events
                if e.get("details", {}).get("username") == username or e.get("userId") == username or f"usr-uuid-{username}" == e.get("userId")
            ]
            if not matching_events:
                warnings.append(f"Ground truth defined for '{username}' but no corresponding events found in dataset.")

        # Check every user in user_events has ground truth
        for u in user_events:
            clean_u = u.replace("usr-uuid-", "")
            if clean_u not in ground_truth and u not in ground_truth:
                errors.append(f"Missing ground truth for user '{u}'.")

        is_valid = len(errors) == 0
        return ValidationReport(
            is_valid=is_valid,
            total_events=len(events),
            total_journeys=len(ground_truth),
            category_counts=category_counts,
            errors=errors,
            warnings=warnings
        )
