"""Bounded inter-arrival baseline for periodic session metadata."""

from __future__ import annotations

import math


class BeaconingRuleDetector:
    name = "BeaconingRuleDetector"
    method = "inter_arrival_cv_rule"
    model_status = "baseline_rule"
    model_version = "1.0.0"

    def predict(self, flows: list[dict]) -> dict:
        intervals = [float(flow.get("iat", 0) or 0) for flow in flows if float(flow.get("iat", 0) or 0) > 0]
        if len(intervals) < 8:
            return self._result(False, 0.0, [])
        mean = sum(intervals) / len(intervals)
        deviation = math.sqrt(sum((value - mean) ** 2 for value in intervals) / len(intervals))
        coefficient = deviation / max(mean, 1e-9)
        triggered = coefficient <= 0.08 and 30 <= mean <= 3600
        confidence = min(0.97, 0.82 + (0.08 - coefficient) * 1.5) if triggered else 1.0 - min(0.4, coefficient / 4)
        evidence = [f"Inter-arrival CV {coefficient:.3f}", f"{len(intervals)} intervals; mean {mean:.1f}s"] if triggered else []
        return self._result(triggered, confidence, evidence)

    def _result(self, triggered: bool, confidence: float, evidence: list[str]) -> dict:
        return {
            "threat": "C2 Beacon" if triggered else "Benign",
            "confidence": round(confidence if triggered else 1.0 - confidence, 4),
            "is_beacon": triggered,
            "subtype": "Periodic session behavior",
            "model": self.name,
            "method": self.method,
            "model_status": self.model_status,
            "model_version": self.model_version,
            "evidence": evidence,
            "limitations": ["Periodic software updates, health checks, and keep-alives can resemble beaconing; verify endpoint context."],
            "mitre": ["T1071"],
        }
