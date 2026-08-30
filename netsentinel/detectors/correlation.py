"""
netsentinel/detectors/correlation.py
======================================
Cross-detector correlation engine.

Aggregates independent signals from multiple detectors for the same source
into composite high-confidence alerts. Implements:

  - Time-windowed evidence accumulation per source identity
  - Deduplication: storm suppression via alert cooldown
  - Composite kill-chain timeline (DNS anomaly → beacon → upload)
  - Alert expiration
  - Graph-like evidence linking (flow IDs, detector names, timestamps)

IMPORTANT DESIGN RULE:
  A single weak signal NEVER produces a composite alert.
  Multiple INDEPENDENT signals are required. The weight of each
  signal and the combination rules are explicit and configurable.
"""

from __future__ import annotations

import time
from collections import defaultdict
from typing import Any


# ── Configuration ─────────────────────────────────────────────────────────────
_WINDOW_SECONDS = 600       # 10-minute correlation window
_COOLDOWN_SECONDS = 120     # minimum gap between composite alerts per source
_MIN_SIGNALS = 2            # minimum independent detector signals to correlate
_MIN_COMPOSITE_SCORE = 0.65 # minimum weighted score for composite alert


# Signal weights (sum should ≤ 1.5 so a single 0.97 confidence never fires alone)
_SIGNAL_WEIGHTS = {
    "DDoS":                              0.80,
    "C2 Beaconing":                      0.65,
    "Port Scan":                         0.55,
    "DGA":                               0.60,
    "DNS Tunnel":                        0.65,
    "Data Exfiltration":                 0.70,
    "Suspicious Legitimate-Service Activity": 0.55,
    "Encrypted Malware":                 0.50,
}


class CorrelationEngine:
    """
    Aggregates detector results by source identity and time window.

    Records every fired alert, then periodically evaluates whether multiple
    independent signals from the same source constitute a higher-confidence
    composite alert.
    """

    name = "CorrelationEngine"
    method = "correlation"
    model_version = "1.1.0"

    def __init__(
        self,
        window_seconds: int = _WINDOW_SECONDS,
        cooldown_seconds: int = _COOLDOWN_SECONDS,
        min_signals: int = _MIN_SIGNALS,
        min_score: float = _MIN_COMPOSITE_SCORE,
    ) -> None:
        self.window_s   = window_seconds
        self.cooldown_s = cooldown_seconds
        self.min_signals = min_signals
        self.min_score  = min_score
        # {src_ip: [alert_record, ...]}
        self._evidence: dict[str, list[dict]] = defaultdict(list)
        # {src_ip: last_composite_alert_time}
        self._last_composite: dict[str, float] = {}
        print(f"  [OK] {self.name} loaded "
              f"(window={window_seconds}s, min_signals={min_signals})")

    # ------------------------------------------------------------------
    def record(self, alert: dict[str, Any]) -> None:
        """Record a fired alert for correlation."""
        if not alert:
            return
        src = (
            alert.get("source_identity")
            or alert.get("source_ip")
            or alert.get("src_ip", "unknown")
        )
        self._evidence[src].append({
            "recorded_at": time.time(),
            "threat_class": alert.get("threat_class", ""),
            "confidence":   alert.get("confidence", 0.0),
            "detector":     alert.get("detector", ""),
            "flow_id":      alert.get("flow_id", ""),
            "evidence":     alert.get("supporting_evidence", []),
            "mitre":        alert.get("mitre_attack_techniques", []),
        })
        self._evict_old(src)

    # ------------------------------------------------------------------
    def evaluate(self, src_ip: str) -> dict[str, Any] | None:
        """
        Evaluate whether accumulated evidence for src_ip constitutes
        a composite alert. Returns a composite alert dict or None.
        """
        self._evict_old(src_ip)
        records = self._evidence.get(src_ip, [])

        if len(records) < self.min_signals:
            return None

        # Cooldown: don't spam composite alerts
        now = time.time()
        last = self._last_composite.get(src_ip, 0)
        if now - last < self.cooldown_s:
            return None

        # Collect unique threat classes and compute weighted score
        seen_classes = {}
        for r in records:
            tc = r["threat_class"]
            if tc not in seen_classes or r["confidence"] > seen_classes[tc]["confidence"]:
                seen_classes[tc] = r

        if len(seen_classes) < self.min_signals:
            return None

        weighted_score = sum(
            _SIGNAL_WEIGHTS.get(tc, 0.40) * info["confidence"]
            for tc, info in seen_classes.items()
        )

        if weighted_score < self.min_score:
            return None

        # Build composite alert
        self._last_composite[src_ip] = now
        composite_confidence = min(0.95, weighted_score / len(seen_classes))

        # Build kill-chain timeline
        timeline = sorted(records, key=lambda r: r["recorded_at"])
        chain_description = " → ".join(
            f"{r['threat_class']} ({r['detector']})"
            for r in timeline
        )

        # Gather all MITRE techniques
        all_mitre: list[str] = []
        for r in records:
            all_mitre.extend(r.get("mitre", []))
        all_mitre = list(dict.fromkeys(all_mitre))  # deduplicate, preserve order

        severity = "critical" if composite_confidence >= 0.85 else "high"

        return {
            "alert_type": "composite",
            "source_identity": src_ip,
            "threat_class": "Correlated Multi-Signal Threat",
            "severity": severity,
            "confidence": round(composite_confidence, 4),
            "composite_score": round(weighted_score, 4),
            "independent_signals": len(seen_classes),
            "signal_classes": list(seen_classes.keys()),
            "kill_chain_timeline": chain_description,
            "related_flow_ids": [r["flow_id"] for r in records if r.get("flow_id")],
            "supporting_evidence": [
                f"[{r['detector']}] {e}"
                for r in records
                for e in r.get("evidence", [])
            ],
            "mitre_attack_techniques": all_mitre,
            "read_only": True,
            "payload_decrypted": False,
            "limitations": [
                "Composite confidence is bounded — individual detectors may have FP bias.",
                "No payload decryption was performed.",
                "Correlation is metadata-only and probabilistic.",
            ],
        }

    def get_all_composites(self) -> list[dict[str, Any]]:
        """Evaluate and return all active composite alerts across all sources."""
        composites = []
        for src_ip in list(self._evidence.keys()):
            result = self.evaluate(src_ip)
            if result:
                composites.append(result)
        return composites

    def get_evidence_graph(self) -> dict[str, Any]:
        """
        Export the current evidence graph as JSON-serializable structure.
        Nodes: sources, destinations, detectors, threat classes.
        Edges: detected, correlated.
        """
        nodes: list[dict] = []
        edges: list[dict] = []
        seen_nodes: set = set()

        for src, records in self._evidence.items():
            if src not in seen_nodes:
                nodes.append({"id": src, "type": "internal_source"})
                seen_nodes.add(src)
            for r in records:
                det = r["detector"]
                tc  = r["threat_class"]
                if det not in seen_nodes:
                    nodes.append({"id": det, "type": "detector"})
                    seen_nodes.add(det)
                if tc not in seen_nodes:
                    nodes.append({"id": tc, "type": "threat_class"})
                    seen_nodes.add(tc)
                edges.append({
                    "from": src, "to": tc,
                    "label": "triggered",
                    "detector": det,
                    "confidence": r["confidence"],
                    "at": r["recorded_at"],
                })

        return {"nodes": nodes, "edges": edges}

    def _evict_old(self, src_ip: str) -> None:
        cutoff = time.time() - self.window_s
        if src_ip in self._evidence:
            self._evidence[src_ip] = [
                r for r in self._evidence[src_ip]
                if r["recorded_at"] >= cutoff
            ]
            if not self._evidence[src_ip]:
                del self._evidence[src_ip]
