"""Stateful, metadata-only reconnaissance and port-scan detector."""

from __future__ import annotations

from typing import Any

_DEFAULT_HORIZONTAL_DST_THRESHOLD = 20
_DEFAULT_VERTICAL_PORT_THRESHOLD = 30
_DEFAULT_STEALTH_THRESHOLD = 10
_DEFAULT_PAIR_THRESHOLD = 24
_DEFAULT_MIN_CONFIDENCE = 0.55


class ReconnaissanceRuleDetector:
    """Classify bounded per-source fan-out without probing or payload access."""

    name = "ReconnaissanceRuleDetector"
    method = "rule"
    model_status = "baseline_rule"
    model_version = "1.2.0"

    def __init__(
        self,
        horizontal_dst_threshold: int = _DEFAULT_HORIZONTAL_DST_THRESHOLD,
        vertical_port_threshold: int = _DEFAULT_VERTICAL_PORT_THRESHOLD,
        stealth_threshold: int = _DEFAULT_STEALTH_THRESHOLD,
        pair_threshold: int = _DEFAULT_PAIR_THRESHOLD,
    ) -> None:
        self.h_thresh = horizontal_dst_threshold
        self.v_thresh = vertical_port_threshold
        self.s_thresh = stealth_threshold
        self.pair_thresh = pair_threshold
        print(f"  [OK] {self.name} loaded (h_dst>{self.h_thresh}, v_port>{self.v_thresh}, pairs>{self.pair_thresh})")

    def predict(self, event: dict[str, Any], host_state: dict[str, Any]) -> dict[str, Any]:
        unique_dsts = len(host_state.get("destinations", set()))
        unique_ports = len(host_state.get("ports", set()))
        total_flows = int(host_state.get("flows", 0))
        unique_pairs = len(host_state.get("destination_port_pairs", set()))
        first_seen = float(host_state.get("first_seen", 0) or 0)
        last_seen = float(host_state.get("last_seen", 0) or 0)
        window_seconds = max(last_seen - first_seen, 0.0)
        probes_per_minute = total_flows / max(window_seconds / 60.0, 1.0)

        features = event.get("features", {})
        syn = float(features.get("SYN Flag Count", 0) or 0)
        ack = float(features.get("ACK Flag Count", 0) or 0)
        syn_only_ratio = syn / max(syn + ack, 1.0)
        packet_bytes = float(features.get("Fwd Packets Length Total", 1000) or 0)
        total_packets = max(float(features.get("Total Fwd Packets", 1) or 1), 1.0)
        avg_payload = packet_bytes / total_packets
        low_payload = avg_payload < 80.0

        triggered = False
        subtype = "unknown"
        confidence = 0.0
        evidence: list[str] = []

        if unique_dsts >= self.s_thresh and unique_ports >= 3 and unique_pairs >= self.pair_thresh:
            triggered = True
            subtype = "Mixed Host and Service Scan"
            confidence = min(0.97, 0.66 + min(unique_pairs / self.pair_thresh, 3.0) * 0.09)
            evidence.extend((
                f"Unique target-port pairs: {unique_pairs} (threshold: {self.pair_thresh})",
                f"Host fan-out: {unique_dsts}; port fan-out: {unique_ports}",
            ))
        elif unique_dsts >= self.h_thresh:
            triggered = True
            subtype = "Horizontal Scan"
            confidence = min(0.97, _DEFAULT_MIN_CONFIDENCE + (unique_dsts / self.h_thresh - 1) * 0.15)
            evidence.append(f"Unique destinations: {unique_dsts} (threshold: {self.h_thresh})")
        elif unique_ports >= self.v_thresh and unique_dsts <= 3:
            triggered = True
            subtype = "Vertical Scan"
            confidence = min(0.97, _DEFAULT_MIN_CONFIDENCE + (unique_ports / self.v_thresh - 1) * 0.12)
            evidence.extend((f"Unique ports: {unique_ports} (threshold: {self.v_thresh})", f"Unique destinations: {unique_dsts}"))
        elif unique_dsts >= self.s_thresh and total_flows <= self.s_thresh * 3 and unique_pairs >= self.s_thresh:
            triggered = True
            subtype = "Stealth Scan"
            confidence = min(0.78, 0.58 + min(unique_pairs / self.s_thresh, 2.0) * 0.08)
            evidence.append(f"Low-rate probe: {unique_dsts} destinations across {unique_pairs} target-port pairs")

        if triggered:
            if syn_only_ratio > 0.7:
                confidence = min(0.97, confidence + 0.05)
                evidence.append(f"SYN-only ratio: {syn_only_ratio:.2f}")
            if low_payload:
                evidence.append(f"Low avg payload: {avg_payload:.0f} bytes")
            evidence.append(f"Probe rate: {probes_per_minute:.1f} flows/min over {window_seconds:.1f}s")

        return {
            "threat": "Port Scan" if triggered else "Benign",
            "confidence": round(confidence if triggered else 1.0, 4),
            "triggered": triggered,
            "subtype": subtype,
            "model": self.name,
            "method": self.method,
            "model_status": self.model_status,
            "model_version": self.model_version,
            "evidence": evidence,
            "feature_snapshot": {
                "unique_destinations": unique_dsts,
                "unique_ports": unique_ports,
                "unique_target_port_pairs": unique_pairs,
                "total_flows": total_flows,
                "window_seconds": round(window_seconds, 3),
                "probes_per_minute": round(probes_per_minute, 3),
                "syn_only_ratio": round(syn_only_ratio, 3),
                "avg_payload_bytes": round(avg_payload, 1),
            },
            "limitations": [
                "Authorized scanners and network-management tools can trigger this detector.",
                "Stealth scans spread across bounded-state windows can be missed.",
                "This is an explainable threshold-based baseline, not a trained classifier.",
            ],
            "mitre": ["T1046"],
        }