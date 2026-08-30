"""Metadata-only volumetric flood baseline used when ONNX is unavailable."""

from __future__ import annotations

from typing import Any


class VolumetricFloodRuleDetector:
    """Require a rate spike plus a transport imbalance before flagging."""

    name = "VolumetricFloodRuleDetector"
    method = "rate_and_handshake_rule"
    model_status = "baseline_rule"
    model_version = "1.0.0"

    def predict(self, event: dict[str, Any]) -> dict[str, Any]:
        features = event.get("features", {})
        packets_per_second = float(features.get("Flow Packets/s", 0) or 0)
        bytes_per_second = float(features.get("Flow Bytes/s", 0) or 0)
        syn_count = float(features.get("SYN Flag Count", 0) or 0)
        ack_count = float(features.get("ACK Flag Count", 0) or 0)
        protocol = int(features.get("Protocol", 0) or 0)
        rate_signal = packets_per_second >= 50_000 or bytes_per_second >= 5_000_000
        handshake_signal = syn_count > ack_count or (protocol == 17 and packets_per_second >= 50_000)
        triggered = rate_signal and handshake_signal
        confidence = 0.96 if triggered else 1.0 - min(0.4, packets_per_second / 500_000)
        evidence = [
            f"Flow rate: {packets_per_second:,.0f} packets/s; {bytes_per_second:,.0f} bytes/s",
            f"Handshake metadata: SYN={syn_count:.0f}, ACK={ack_count:.0f}",
        ]
        if not triggered:
            evidence = []
        return {
            "threat": "DDoS" if triggered else "Benign",
            "confidence": round(confidence, 4),
            "triggered": triggered,
            "is_attack": triggered,
            "subtype": "Volumetric flood-like behavior",
            "model": self.name,
            "method": self.method,
            "model_status": self.model_status,
            "model_version": self.model_version,
            "evidence": evidence,
            "feature_snapshot": {
                "flow_packets_per_second": packets_per_second,
                "flow_bytes_per_second": bytes_per_second,
                "syn_count": syn_count,
                "ack_count": ack_count,
            },
            "limitations": [
                "A rate spike is a behavioral signal, not proof of a distributed attack.",
                "Legitimate load tests and flash crowds require operator context.",
                "This fallback is a rule baseline, not a trained DDoS model.",
            ],
            "mitre": ["T1498"],
        }
