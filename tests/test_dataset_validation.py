"""
AuthDrift: Unit Tests for Synthetic Dataset Validation (Person 1 Task 1).
Validates schema compliance, metadata structure, academic research citations,
session consistency, and fail-closed error detection on corrupted datasets.
"""

import copy
import os
import pytest

from backend.synthetic_data.dataset_validator import DatasetValidator
from backend.synthetic_data.research_dataset_generator import (
    generate_research_synthetic_dataset
)


class TestDatasetValidator:
    """Tests for DatasetValidator functionality and invariants."""

    @pytest.fixture(autouse=True)
    def setup_data(self):
        self.validator = DatasetValidator()
        self.dataset = generate_research_synthetic_dataset()

    def test_official_research_dataset_passes_validation(self):
        """The generated research benchmark dataset must pass validation with 0 errors."""
        report = self.validator.validate_dataset(self.dataset)
        assert report.is_valid is True
        assert len(report.errors) == 0
        assert report.total_events > 150
        assert report.total_journeys == 145

    def test_file_validation_from_disk(self):
        """Validates that the saved JSON file on disk passes validation."""
        path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "sample-data", "research_paper_synthetic_dataset.json")
        report = self.validator.validate_file(path)
        assert report.is_valid is True
        assert len(report.errors) == 0

    def test_validation_fails_on_missing_metadata(self):
        """Metadata section must be present and include required fields."""
        corrupted = copy.deepcopy(self.dataset)
        del corrupted["metadata"]
        report = self.validator.validate_dataset(corrupted)
        assert report.is_valid is False
        assert any("Missing required root key: metadata" in e for e in report.errors)

    def test_validation_fails_on_missing_required_event_fields(self):
        """Events must contain required fields: id, time, type, userId, details."""
        corrupted = copy.deepcopy(self.dataset)
        del corrupted["events"][0]["id"]
        report = self.validator.validate_dataset(corrupted)
        assert report.is_valid is False
        assert any("missing required fields" in e for e in report.errors)

    def test_validation_fails_on_out_of_order_timestamps(self):
        """Timestamps within a user's journey must be chronologically non-decreasing."""
        corrupted = copy.deepcopy(self.dataset)
        sess_events = [e for e in corrupted["events"] if e.get("sessionId") == "sess-recov-01"]
        assert len(sess_events) >= 2
        # Advance first event to be far after the second
        sess_events[0]["time"] = sess_events[1]["time"] + 10000000

        report = self.validator.validate_dataset(corrupted)
        assert report.is_valid is False
        assert any("Chronological violation" in e for e in report.errors)

    def test_validation_fails_on_ground_truth_mismatch(self):
        """Ground truth must exist for all users present in events."""
        corrupted = copy.deepcopy(self.dataset)
        del corrupted["ground_truth"]["emp_recov_01"]
        report = self.validator.validate_dataset(corrupted)
        assert report.is_valid is False
        assert any("emp_recov_01" in e and "Missing ground truth" in e for e in report.errors)

    def test_academic_citations_integrity(self):
        """Verifies that all 7 mandatory research citations are present in the benchmark."""
        citations = [p["citation"] for p in self.dataset["metadata"]["research_papers"]]
        assert any("Lyastani" in c for c in citations)
        assert any("Wiefling" in c for c in citations)
        assert any("Kent" in c for c in citations)
        assert any("Bonneau" in c for c in citations)
        assert any("Alaca" in c for c in citations)
        assert any("Freeman" in c for c in citations)
        assert any("Thomas" in c for c in citations)
