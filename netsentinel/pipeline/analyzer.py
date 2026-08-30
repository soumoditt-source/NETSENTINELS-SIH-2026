"""Flow Analyzer — Routes incoming events to the correct AI models and rule detectors.

This is the central orchestrator. It receives normalized events (from the
traffic simulator or the ingest adapters) and routes them through:
  1. ML models (DDoS, C2 Beacon, DGA, Encrypted Traffic)
  2. Rule-based detectors (Reconnaissance, Exfiltration, Legit-Service C2)
  3. Correlation engine (cross-detector risk aggregation)

The StateManager is injected so that stateful features (per-host destination
fan-out, byte volumes, service labels) are available to rule detectors without
those detectors needing to maintain their own state.
"""
from netsentinel.models.registry import ModelRegistry
from netsentinel.pipeline.alert_manager import AlertManager
from netsentinel.features.state_manager import StateManager
from netsentinel.config import THRESHOLDS
from netsentinel.ingest.flow_adapter import normalized_to_analyzer_event
import math
from collections import Counter
from netsentinel.forensics import TemporalForensics


class FlowAnalyzer:
    """Routes flows to models/detectors and collects alerts."""

    def __init__(self, registry: ModelRegistry, alert_manager: AlertManager):
        self.registry = registry
        self.alert_manager = alert_manager
        self.state_manager = StateManager(ttl_seconds=300)
        self.temporal_forensics = TemporalForensics(window_seconds=300, max_events=50_000)
        self.flows_processed = 0

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def analyze_flow(self, event: dict) -> dict | None:
        """
        Analyze a single event and return an alert if a threat is detected.

        Event types:
          - ``type="dns"``     → DGA detector
          - ``type="session"`` → C2 Beacon detector
          - ``type="flow"``    → DDoS, Recon, Exfil, ETT, Legit-Service C2

        Returns:
            Alert dict if threat detected, None otherwise.
        """
        if hasattr(event, "model_dump"):
            event = normalized_to_analyzer_event(event)
        self.flows_processed += 1
        self.temporal_forensics.observe(event)
        event_type = event.get("type", "flow")

        if event_type == "dns" and (self.registry.dga or self.registry.dga_rule):
            alert = self._analyze_dns(event)
        elif event_type == "session" and (self.registry.c2 or self.registry.beacon_rule):
            alert = self._analyze_session(event)
        elif event_type == "flow":
            alert = self._analyze_network_flow(event)
        else:
            alert = None

        if alert:
            self.temporal_forensics.record_alert(alert, event.get("observed_at"))
        return alert

    # ------------------------------------------------------------------
    # DNS / DGA
    # ------------------------------------------------------------------

    def _analyze_dns(self, event: dict) -> dict | None:
        """Run DGA detection on a DNS query event."""
        domain = event.get("domain", "")
        if not domain:
            return None

        detector = self.registry.dga or self.registry.dga_rule
        result = detector.predict(domain)

        # Extra heuristic guard: require high Shannon entropy so common CDN
        # domains (e.g. "fonts.gstatic.com") don't get flagged.
        parts = domain.lower().strip().split(".")
        stem = ".".join(parts[:-1]) if len(parts) > 1 else domain
        freq = Counter(stem)
        total = len(stem)
        entropy = (
            -sum((c / total) * math.log2(c / total) for c in freq.values())
            if total > 0
            else 0
        )

        if (
            result["is_malicious"]
            and result["confidence"] >= THRESHOLDS["dga"]
            and entropy > 3.0
        ):
            return self.alert_manager.create_alert(
                result,
                source_ip=event.get("source_ip"),
                flow_meta={
                    **self._flow_meta(event),
                    "domain": domain,
                    "entropy": round(entropy, 3),
                },
            )
        return None

    # ------------------------------------------------------------------
    # Session / C2 Beacon
    # ------------------------------------------------------------------

    def _analyze_session(self, event: dict) -> dict | None:
        """Run C2 Beacon detection on a flow time-series session."""
        flows = event.get("flows", [])
        if not flows:
            return None

        detector = self.registry.c2 or self.registry.beacon_rule
        result = detector.predict(flows)

        if result["is_beacon"] and result["confidence"] >= THRESHOLDS["c2_beacon"]:
            return self.alert_manager.create_alert(
                result,
                source_ip=event.get("source_ip"),
                dest_ip=event.get("dest_ip"),
                flow_meta=self._flow_meta(event),
            )
        return None

    # ------------------------------------------------------------------
    # Network Flow (DDoS · Port Scan · Exfil · ETT · Legit-Service C2)
    # ------------------------------------------------------------------

    def _analyze_network_flow(self, event: dict) -> dict | None:
        """
        Run all applicable detectors on a single network flow event.

        Evaluation order (short-circuit on first high-confidence alert):
          1. DDoS (XGBoost ML)
          2. Reconnaissance / Port Scan (rule-based)
          3. Data Exfiltration (rule-based baseline)
          4. Legitimate-Service C2 (behavioral correlation)
          5. Encrypted Traffic (Transformer ML) — fallback
        """
        features = event.get("features", {})
        alert = None

        # --- Update streaming state for rule detectors -------------------
        host_state = self._get_host_state(event)

        # 1. DDoS ─────────────────────────────────────────────────────────
        if alert is None and self.registry.ddos and features:
            result = self.registry.ddos.predict(features)
            if result["is_attack"] and result["confidence"] >= THRESHOLDS["ddos"]:
                pkt_rate  = features.get("Flow Packets/s", 0)
                byte_rate = features.get("Flow Bytes/s", 0)
                # Guard: real DDoS must show volumetric signature
                if pkt_rate > 100 or byte_rate > 50_000:
                    alert = self.alert_manager.create_alert(
                        result,
                        source_ip=event.get("source_ip"),
                        dest_ip=event.get("dest_ip"),
                        flow_meta=self._flow_meta(event),
                    )

        if alert is None and self.registry.volumetric and features:
            result = self.registry.volumetric.predict(event)
            if result["triggered"] and result["confidence"] >= THRESHOLDS["ddos"]:
                alert = self.alert_manager.create_alert(
                    result,
                    source_ip=event.get("source_ip"),
                    dest_ip=event.get("dest_ip"),
                    flow_meta=self._flow_meta(event),
                )

        # 2. Reconnaissance / Port Scan ───────────────────────────────────
        if alert is None and self.registry.recon:
            result = self.registry.recon.predict(event, host_state)
            if result["triggered"] and result["confidence"] >= THRESHOLDS["port_scan"]:
                alert = self.alert_manager.create_alert(
                    result,
                    source_ip=event.get("source_ip"),
                    dest_ip=event.get("dest_ip"),
                    flow_meta=self._flow_meta(event),
                )

        # 3. Data Exfiltration ────────────────────────────────────────────
        if alert is None and self.registry.exfil:
            result = self.registry.exfil.predict(event, host_state)
            if result["triggered"] and result["confidence"] >= THRESHOLDS["data_exfiltration"]:
                alert = self.alert_manager.create_alert(
                    result,
                    source_ip=event.get("source_ip"),
                    dest_ip=event.get("dest_ip"),
                    flow_meta=self._flow_meta(event),
                )

        # 4. Legitimate-Service C2 ────────────────────────────────────────
        if alert is None and self.registry.c2_legit:
            result = self.registry.c2_legit.predict(event, host_state)
            if result.get("triggered") and result["confidence"] >= 0.75:
                alert = self.alert_manager.create_alert(
                    result,
                    source_ip=event.get("source_ip"),
                    dest_ip=event.get("dest_ip"),
                    flow_meta=self._flow_meta(event),
                )

        # 5. Encrypted Traffic (fallback) ─────────────────────────────────
        if alert is None and self.registry.cic_xgb and features:
            result = self.registry.cic_xgb.predict(features)
            coverage = result.get("feature_snapshot", {}).get("feature_coverage", 0.0)
            if result["is_attack"] and coverage >= 0.35:
                alert = self.alert_manager.create_alert(
                    result,
                    source_ip=event.get("source_ip"),
                    dest_ip=event.get("dest_ip"),
                    flow_meta=self._flow_meta(event),
                )

        if alert is None and self.registry.ett and features:
            result = self.registry.ett.predict(features)
            if result["is_vpn"] and result["confidence"] >= THRESHOLDS["encrypted_malware"]:
                alert = self.alert_manager.create_alert(
                    result,
                    source_ip=event.get("source_ip"),
                    dest_ip=event.get("dest_ip"),
                )

        # Optional: run correlation engine on any generated alert
        if alert and self.registry.correlation:
            self.registry.correlation.record(alert)

        return alert

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _get_host_state(self, event: dict) -> dict:
        """
        Update and return the streaming host state for an event.

        Falls back gracefully if the event is a raw dict (simulator format)
        rather than a NormalizedEvent Pydantic object.
        """
        try:
            return self.state_manager.update_state(event)
        except (AttributeError, TypeError):
            # Simulator generates plain dicts — build a minimal host_state
            features = event.get("features", {})
            src = event.get("source_ip", "unknown")
            state = self.state_manager.host_state[src]
            dst = event.get("dest_ip", "")
            port = features.get("Destination Port", 0)
            if dst:
                state["destinations"].add(dst)
            if port:
                state["ports"].add(port)
            bytes_val = features.get("Total Fwd Packets", 0) * 1500
            state["bytes_out"] += bytes_val
            state["flows"] += 1
            state["last_seen"] = float(event.get("observed_at", __import__("time").time()))
            return dict(state)

    def get_stats(self) -> dict:
        """Return pipeline statistics."""
        return {
            "flows_processed": self.flows_processed,
            "state_manager_hosts": len(self.state_manager.host_state),
            "temporal_forensics": self.temporal_forensics.summary(),
            **self.alert_manager.get_stats(),
        }

    @staticmethod
    def _flow_meta(event: dict) -> dict:
        """Carry event provenance into alert records without storing payloads."""

        return {
            "flow_id": event.get("flow_id", ""),
            "event_id": event.get("event_id", ""),
            "observed_at": event.get("observed_at"),
        }
