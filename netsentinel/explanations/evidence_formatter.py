"""Stable formatting for detector evidence in API and UI responses."""

from typing import Any


def format_evidence(result: dict[str, Any]) -> dict[str, Any]:
    """Separate observed fields from inferred detector output."""

    return {
        "observed": list(result.get("evidence", [])),
        "inference": {
            "threat": result.get("threat", "unknown"),
            "confidence": result.get("confidence", 0.0),
            "triggered": result.get("triggered", result.get("is_attack", False)),
        },
        "technical": result.get("feature_snapshot", {}),
        "provenance": {
            "detector": result.get("model", result.get("detector", "unknown")),
            "method": result.get("method", "unknown"),
            "model_version": result.get("model_version", "unknown"),
        },
    }
