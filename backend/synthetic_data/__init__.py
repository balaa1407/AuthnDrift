"""
AuthDrift: Synthetic Data Generator based on Empirical Authentication Research Papers.
"""

from backend.synthetic_data.research_dataset_generator import (
    generate_research_synthetic_dataset,
    save_synthetic_dataset,
    RESEARCH_PAPERS,
    KNOWN_BENCHMARK_DEVICES
)

__all__ = [
    "generate_research_synthetic_dataset",
    "save_synthetic_dataset",
    "RESEARCH_PAPERS",
    "KNOWN_BENCHMARK_DEVICES"
]
