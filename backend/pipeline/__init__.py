"""
AuthDrift: End-to-End Pipeline Coordinator.
Connects raw event extraction/normalization, journey reconstruction,
and Balaa's AuthDriftEngine security detection.
"""

from backend.pipeline.pipeline import AuthDriftPipeline, PipelineExecutionResult

__all__ = ["AuthDriftPipeline", "PipelineExecutionResult"]

