"""
AuthDrift: End-to-End Pipeline Coordinator.
Connects raw event extraction/normalization, journey reconstruction,
and AuthDriftEngine security detection.
"""

from backend.pipeline.pipeline import AuthDriftPipeline, PipelineExecutionResult

__all__ = ["AuthDriftPipeline", "PipelineExecutionResult"]

