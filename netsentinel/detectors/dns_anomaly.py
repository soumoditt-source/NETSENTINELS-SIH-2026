"""Explainable DNS anomaly baseline for environments without the DGA ONNX model."""

from __future__ import annotations

import math
from collections import Counter


class DNSAnomalyRuleDetector:
    name = "DNSAnomalyRuleDetector"
    method = "entropy_length_rule"
    model_status = "baseline_rule"
    model_version = "1.0.0"

    def predict(self, domain: str) -> dict:
        labels = [label for label in domain.lower().strip(".").split(".") if label]
        stem = labels[-2] if len(labels) >= 2 else (labels[0] if labels else "")
        counts = Counter(stem)
        length = len(stem)
        entropy = -sum((count / length) * math.log2(count / length) for count in counts.values()) if length else 0.0
        digit_ratio = sum(character.isdigit() for character in stem) / max(length, 1)
        triggered = length >= 12 and (entropy >= 2.8 or digit_ratio >= 0.25)
        confidence = min(0.94, 0.78 + max(entropy - 2.8, 0) * 0.10 + digit_ratio * 0.08) if triggered else 1.0 - min(0.4, entropy / 20)
        return {
            "threat": "DGA" if triggered else "Benign",
            "confidence": round(confidence, 4),
            "is_malicious": triggered,
            "subtype": "High-entropy DNS label",
            "model": self.name,
            "method": self.method,
            "model_status": self.model_status,
            "model_version": self.model_version,
            "evidence": [f"DNS stem entropy {entropy:.2f}", f"Stem length {length} characters", f"Digit ratio {digit_ratio:.2f}"] if triggered else [],
            "feature_snapshot": {"entropy": round(entropy, 3), "stem_length": length, "digit_ratio": round(digit_ratio, 3)},
            "limitations": ["Entropy and length are not proof of DGA; CDNs, tracking IDs, and generated service names can look similar."],
            "mitre": ["T1568"],
        }
