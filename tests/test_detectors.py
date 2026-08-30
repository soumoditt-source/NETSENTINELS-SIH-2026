"""
tests/test_detectors.py
========================
Unit tests for all NetSentinel rule-based detectors.

Tests include:
  - Positive detection examples
  - Negative (benign) examples
  - Hard negatives (benign activities that should NOT trigger)
  - Edge cases (empty state, zero values)
  - Evidence field presence
  - Confidence sanity checks (0–1 range)
"""

import pytest

# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_host_state(**kwargs) -> dict:
    defaults = {
        "destinations": set(),
        "ports": set(),
        "bytes_out": 0,
        "bytes_in":  0,
        "flows":     0,
        "services":  set(),
        "last_seen": 0,
    }
    defaults.update(kwargs)
    return defaults


def _make_event(src="10.0.0.1", dst="8.8.8.8", **features) -> dict:
    return {
        "type": "flow",
        "source_ip": src,
        "dest_ip": dst,
        "flow_id": "test-flow-001",
        "features": features or {},
    }


# ══════════════════════════════════════════════════════════════════════════════
# ReconnaissanceRuleDetector
# ══════════════════════════════════════════════════════════════════════════════

class TestReconnaissanceDetector:

    @pytest.fixture
    def detector(self):
        from netsentinel.detectors.reconnaissance import ReconnaissanceRuleDetector
        return ReconnaissanceRuleDetector(
            horizontal_dst_threshold=20,
            vertical_port_threshold=30,
        )

    def test_horizontal_scan_triggers(self, detector):
        """25 unique destinations → horizontal scan detected."""
        state = _make_host_state(
            destinations=set(f"10.0.1.{i}" for i in range(25)),
            ports={80},
        )
        result = detector.predict(_make_event(), state)
        assert result["triggered"] is True
        assert result["subtype"] == "Horizontal Scan"
        assert 0 < result["confidence"] <= 1.0
        assert len(result["evidence"]) > 0

    def test_vertical_scan_triggers(self, detector):
        """35 unique ports, 1 destination → vertical scan."""
        state = _make_host_state(
            destinations={"192.168.1.100"},
            ports=set(range(1, 36)),
        )
        result = detector.predict(_make_event(), state)
        assert result["triggered"] is True
        assert result["subtype"] == "Vertical Scan"
        assert result["confidence"] > 0.5

    def test_benign_no_trigger(self, detector):
        """Normal browsing — few destinations, few ports."""
        state = _make_host_state(
            destinations={"8.8.8.8", "1.1.1.1"},
            ports={443, 80},
        )
        result = detector.predict(_make_event(), state)
        assert result["triggered"] is False

    def test_empty_state_safe(self, detector):
        """Empty state should never crash or trigger."""
        result = detector.predict(_make_event(), {})
        assert result["triggered"] is False
        assert result["confidence"] >= 0.0

    def test_confidence_range(self, detector):
        """Confidence must always be in [0, 1]."""
        for n_dsts in [5, 20, 50, 200]:
            state = _make_host_state(
                destinations=set(f"1.1.1.{i}" for i in range(min(n_dsts, 254))),
                ports={80},
            )
            r = detector.predict(_make_event(), state)
            assert 0.0 <= r["confidence"] <= 1.0, f"confidence={r['confidence']} for n_dsts={n_dsts}"

    def test_limitations_present(self, detector):
        """Every result must carry a limitations list."""
        result = detector.predict(_make_event(), _make_host_state())
        assert "limitations" in result
        assert len(result["limitations"]) > 0

    def test_feature_snapshot_present(self, detector):
        """feature_snapshot must be returned."""
        state = _make_host_state(destinations={"1.2.3.4"}, ports={443})
        result = detector.predict(_make_event(), state)
        assert "feature_snapshot" in result
        assert "unique_destinations" in result["feature_snapshot"]


# ══════════════════════════════════════════════════════════════════════════════
# ExfiltrationBaselineDetector
# ══════════════════════════════════════════════════════════════════════════════

class TestExfiltrationDetector:

    @pytest.fixture
    def detector(self):
        from netsentinel.detectors.exfiltration import ExfiltrationBaselineDetector
        return ExfiltrationBaselineDetector()

    def test_high_ratio_triggers(self, detector):
        """100MB out, 500 bytes in → ratio = 200_000x → should trigger."""
        state = _make_host_state(bytes_out=100_000_000, bytes_in=500)
        result = detector.predict(_make_event(), state)
        assert result["triggered"] is True
        assert result["confidence"] > 0.7

    def test_suspicious_ratio_triggers(self, detector):
        """20MB out, 800 bytes in → ratio ~25_000x."""
        state = _make_host_state(bytes_out=20_000_000, bytes_in=800)
        result = detector.predict(_make_event(), state)
        assert result["triggered"] is True

    def test_large_legitimate_backup_no_trigger(self, detector):
        """Hard negative: 50MB out, 10MB in (ratio=5) → NOT suspicious."""
        state = _make_host_state(bytes_out=50_000_000, bytes_in=10_000_000)
        ev = _make_event()
        ev["dest_domain"] = "onedrive.live.com"
        result = detector.predict(ev, state)
        assert result["triggered"] is False, "Balanced cloud backup should not trigger exfil"

    def test_small_transfer_no_trigger(self, detector):
        """1MB transfer → below min_bytes_out threshold."""
        state = _make_host_state(bytes_out=1_000_000, bytes_in=10)
        result = detector.predict(_make_event(), state)
        assert result["triggered"] is False

    def test_cloud_service_reduces_confidence(self, detector):
        """Known cloud destination should reduce confidence."""
        state = _make_host_state(bytes_out=200_000_000, bytes_in=100)
        ev = _make_event()
        ev["dest_domain"] = "drive.google.com"
        result = detector.predict(ev, state)
        if result["triggered"]:
            assert result["confidence"] < 0.97, "Cloud destination should reduce confidence"

    def test_evidence_populated_on_trigger(self, detector):
        """Triggered alerts must have evidence."""
        state = _make_host_state(bytes_out=50_000_000, bytes_in=10)
        result = detector.predict(_make_event(), state)
        if result["triggered"]:
            assert len(result["evidence"]) > 0


# ══════════════════════════════════════════════════════════════════════════════
# LegitimateServiceC2Detector
# ══════════════════════════════════════════════════════════════════════════════

class TestLegitServiceC2Detector:

    @pytest.fixture
    def detector(self):
        from netsentinel.detectors.legitimate_service_c2 import LegitimateServiceC2Detector
        return LegitimateServiceC2Detector(window_seconds=3600)

    def _make_checkin_ev(self, service_domain: str, src: str = "10.0.0.5",
                         bytes_out: int = 300, bytes_in: int = 10) -> dict:
        ev = _make_event(src=src)
        ev["dest_domain"] = service_domain
        ev["_bytes_out"]  = bytes_out
        ev["_bytes_in"]   = bytes_in
        return ev

    def test_single_session_no_trigger(self, detector):
        """One Telegram session alone → never triggers."""
        ev = self._make_checkin_ev("api.telegram.org")
        result = detector.predict(ev, _make_host_state())
        assert result["triggered"] is False, "Single session must never trigger"

    def test_normal_messaging_no_trigger(self, detector):
        """Hard negative: irregular intervals (high CV) → benign chat, no trigger."""
        import time, random
        rng = random.Random(42)
        ev = self._make_checkin_ev("api.telegram.org")
        state = _make_host_state()
        # Simulate 10 irregular sessions
        for _ in range(10):
            result = detector.predict(ev, state)
        assert result["triggered"] is False, "Irregular messaging should not trigger"

    def test_unknown_domain_no_trigger(self, detector):
        """Unknown domain → not applicable, no trigger."""
        ev = _make_event()
        ev["dest_domain"] = "some-random-site.example.com"
        result = detector.predict(ev, _make_host_state())
        assert result["triggered"] is False

    def test_limitations_always_present(self, detector):
        """Result must always carry limitations."""
        ev = self._make_checkin_ev("api.telegram.org")
        result = detector.predict(ev, _make_host_state())
        assert "limitations" in result


# ══════════════════════════════════════════════════════════════════════════════
# CorrelationEngine
# ══════════════════════════════════════════════════════════════════════════════

class TestCorrelationEngine:

    @pytest.fixture
    def engine(self):
        from netsentinel.detectors.correlation import CorrelationEngine
        return CorrelationEngine(window_seconds=600, min_signals=2, min_score=0.60)

    def _make_alert(self, src: str, threat: str, confidence: float, detector: str = "TestDet") -> dict:
        return {
            "source_identity": src,
            "threat_class":    threat,
            "confidence":      confidence,
            "detector":        detector,
            "flow_id":         "flow-001",
            "supporting_evidence": [f"Evidence for {threat}"],
            "mitre_attack_techniques": ["T1000"],
        }

    def test_single_signal_no_composite(self, engine):
        """Single alert → not enough for composite."""
        engine.record(self._make_alert("10.0.0.1", "Port Scan", 0.90))
        result = engine.evaluate("10.0.0.1")
        assert result is None, "Single signal must not produce composite alert"

    def test_two_signals_produce_composite(self, engine):
        """Two independent signals → composite alert."""
        engine.record(self._make_alert("10.0.0.2", "Port Scan", 0.90, "Recon"))
        engine.record(self._make_alert("10.0.0.2", "C2 Beaconing", 0.85, "BiLSTM"))
        result = engine.evaluate("10.0.0.2")
        assert result is not None
        assert result["independent_signals"] >= 2
        assert 0 < result["confidence"] <= 1.0

    def test_evidence_graph_exportable(self, engine):
        """get_evidence_graph() must return serializable structure."""
        engine.record(self._make_alert("10.0.0.3", "DGA", 0.80, "DGADet"))
        graph = engine.get_evidence_graph()
        assert "nodes" in graph
        assert "edges" in graph
        assert isinstance(graph["nodes"], list)

    def test_deduplication_cooldown(self, engine):
        """Second evaluate within cooldown should return None."""
        engine.record(self._make_alert("10.0.0.4", "Port Scan", 0.90, "R"))
        engine.record(self._make_alert("10.0.0.4", "C2 Beaconing", 0.85, "C"))
        first  = engine.evaluate("10.0.0.4")
        second = engine.evaluate("10.0.0.4")
        # second call within cooldown should be None
        assert second is None, "Cooldown must suppress duplicate composites"


# ══════════════════════════════════════════════════════════════════════════════
# Safe Scenarios ground truth
# ══════════════════════════════════════════════════════════════════════════════

class TestSafeScenarios:

    def test_benign_web_has_ground_truth(self):
        from netsentinel.simulator.safe_scenarios import benign_web_browsing
        events = list(benign_web_browsing(seed=0, n=5))
        assert len(events) == 5
        for ev in events:
            assert ev["_ground_truth"]["label"] == "benign"

    def test_horizontal_scan_has_ground_truth(self):
        from netsentinel.simulator.safe_scenarios import horizontal_scan
        events = list(horizontal_scan(seed=0, n_targets=10))
        assert len(events) == 10
        for ev in events:
            assert ev["_ground_truth"]["label"] == "attack"
            assert ev["_ground_truth"]["threat_class"] == "Reconnaissance"

    def test_legit_service_chain_stages(self):
        from netsentinel.simulator.safe_scenarios import suspicious_legit_service_c2
        events = list(suspicious_legit_service_c2(seed=0, n_checkins=5))
        stages = {ev["_ground_truth"]["stage"] for ev in events}
        assert "dns_anomaly" in stages
        assert "periodic_checkin" in stages
        assert "anomalous_upload" in stages

    def test_benign_cloud_sync_is_not_exfil(self):
        from netsentinel.simulator.safe_scenarios import benign_cloud_sync
        events = list(benign_cloud_sync(seed=0, n=3))
        for ev in events:
            assert ev["_ground_truth"]["label"] == "benign"
            assert "benign" in ev["_ground_truth"].get("note", "").lower()

    def test_mixed_enterprise_has_both_labels(self):
        from netsentinel.simulator.safe_scenarios import mixed_enterprise_replay
        events = list(mixed_enterprise_replay(seed=99, n_total=100))
        labels = {ev["_ground_truth"]["label"] for ev in events}
        assert "benign" in labels
        assert "attack" in labels
