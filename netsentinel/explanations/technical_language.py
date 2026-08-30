"""Technical explanation rendering kept separate from judge-facing prose."""

from typing import Any


def build_technical_explanation(result: dict[str, Any]) -> dict[str, Any]:
    """Return raw evidence and detector provenance for analyst mode."""

    return {
        "feature_snapshot": result.get("feature_snapshot", {}),
        "supporting_evidence": result.get("evidence", []),
        "detector": result.get("model", result.get("detector", "unknown")),
        "method": result.get("method", "unknown"),
        "model_version": result.get("model_version", "unknown"),
        "limitations": result.get("limitations", []),
        "payload_decrypted": False,
        "read_only": True,
    }
