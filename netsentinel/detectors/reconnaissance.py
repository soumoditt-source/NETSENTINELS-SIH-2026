"""
netsentinel/detectors/reconnaissance.py
=========================================
Stateful heuristic detector for network reconnaissance and port scanning.

Method: rule-based  (NOT a trained ML model)
Status: baseline_rule

Distinguishes three scan subtypes:
  1. Horizontal scan: one port → many destination hosts (fan-out > threshold)
  2. Vertical scan:   many ports → one host (port fan-in > threshold)
  3. Stealth/slow scan: low volume over long interval (detected from state window)

All thresholds are configurable. The host_state dict is supplied by the
StreamingStateManager, which maintains TTL-evicted per-source windows.

Limitations:
  - Authorized vulnerability scanners and network-management tools will trigger
    this detector. Use allowlists in config for known scanners.
  - Low-rate stealth scans spread across multiple TTL windows may be missed.
  - This is NOT a trained XGBoost classifier. It is a deterministic baseline.
"""

from __future__ import annotations
from typing import Any


# ── Configurable thresholds ────────────────────────────────────────────────────
_DEFAULT_HORIZONTAL_DST_THRESHOLD = 20    # unique destinations before flagging
_DEFAULT_VERTICAL_PORT_THRESHOLD = 30     # unique ports before flagging
_DEFAULT_STEALTH_THRESHOLD = 10           # fewer dsts but over a long window
_DEFAULT_MIN_CONFIDENCE = 0.55


class ReconnaissanceRuleDetector:
    """
    Deterministic baseline detector for network scanning.

    Returns a standard evidence dict regardless of whether a threat
    is detected, so the correlation engine can weight the signal.
    """

    name = "ReconnaissanceRuleDetector"
    method = "rule"
    model_status = "baseline_rule"
    model_version = "1.1.0"

    def __init__(
        self,
        horizontal_dst_threshold: int = _DEFAULT_HORIZONTAL_DST_THRESHOLD,
        vertical_port_threshold: int  = _DEFAULT_VERTICAL_PORT_THRESHOLD,
        stealth_threshold: int        = _DEFAULT_STEALTH_THRESHOLD,
    ) -> None:
        self.h_thresh = horizontal_dst_threshold
        self.v_thresh = vertical_port_threshold
        self.s_thresh = stealth_threshold
        print(f"  [OK] {self.name} loaded "
              f"(h_dst>{self.h_thresh}, v_port>{self.v_thresh})")

    # ------------------------------------------------------------------
    def predict(self, event: dict[str, Any], host_state: dict[str, Any]) -> dict[str, Any]:
        """
        Evaluate risk from the host_state window.

        Args:
            event:      Normalized event dict (used for feature snapshot only).
            host_state: Per-source state dict from StateManager — must contain
                        ``destinations`` (set), ``ports`` (set), ``flows`` (int).

        Returns:
            Standard detector result dict.
        """
        unique_dsts  = len(host_state.get("destinations", set()))
        unique_ports = len(host_state.get("ports",        set()))
        total_flows  = host_state.get("flows", 0)

        # SYN-only ratio (if available in event features)
        features = event.get("features", {})
        syn  = features.get("SYN Flag Count", 0)
        ack  = features.get("ACK Flag Count", 0)
        syn_only_ratio = syn / max(syn + ack, 1)

        # Low payload indicator
        pkt_bytes = features.get("Fwd Packets Length Total", 1000)
        total_pkts = max(features.get("Total Fwd Packets", 1), 1)
        avg_payload = pkt_bytes / total_pkts
        low_payload = avg_payload < 80.0

        triggered = False
        subtype = "unknown"
        confidence = 0.0
        evidence: list[str] = []

        # ── Horizontal scan ───────────────────────────────────────────
        if unique_dsts >= self.h_thresh:
            triggered = True
            subtype = "Horizontal Scan"
            # Confidence scales with how far above threshold
            ratio = unique_dsts / self.h_thresh
            confidence = min(0.97, _DEFAULT_MIN_CONFIDENCE + (ratio - 1) * 0.15)
            evidence.append(f"Unique destinations: {unique_dsts} (threshold: {self.h_thresh})")
            if syn_only_ratio > 0.7:
                confidence = min(0.97, confidence + 0.05)
                evidence.append(f"SYN-only ratio: {syn_only_ratio:.2f}")
            if low_payload:
                evidence.append(f"Low avg payload: {avg_payload:.0f} bytes")

        # ── Vertical scan ─────────────────────────────────────────────
        elif unique_ports >= self.v_thresh and unique_dsts <= 3:
            triggered = True
            subtype = "Vertical Scan"
            ratio = unique_ports / self.v_thresh
            confidence = min(0.97, _DEFAULT_MIN_CONFIDENCE + (ratio - 1) * 0.12)
            evidence.append(f"Unique ports: {unique_ports} (threshold: {self.v_thresh})")
            evidence.append(f"Unique destinations: {unique_dsts}")
            if syn_only_ratio > 0.7:
                confidence = min(0.97, confidence + 0.05)
                evidence.append(f"SYN-only ratio: {syn_only_ratio:.2f}")

        # ── Stealth / low-rate scan ───────────────────────────────────
        elif unique_dsts >= self.s_thresh and total_flows < self.s_thresh * 3:
            triggered = True
            subtype = "Stealth Scan"
            confidence = 0.60
            evidence.append(f"Low-rate probe: {unique_dsts} dsts in {total_flows} flows")

        return {
            "threat": "Port Scan" if triggered else "Benign",
            "confidence": round(confidence if triggered else 1.0 - confidence, 4),
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
                "total_flows": total_flows,
                "syn_only_ratio": round(syn_only_ratio, 3),
                "avg_payload_bytes": round(avg_payload, 1),
            },
            "limitations": [
                "Authorized scanners (e.g., Nessus, Nmap in approved windows) will trigger this detector.",
                "Stealth scans spread across TTL window boundaries may be missed.",
                "No ML training — threshold-based heuristic baseline only.",
            ],
            "mitre": ["T1046"],
        }
