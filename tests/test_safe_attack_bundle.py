"""Tests for the deterministic safe metadata test bundle."""

from __future__ import annotations

import json

from netsentinel.ingest.flow_adapter import iter_analyzer_events
from netsentinel.simulator.safe_trace_writer import write_replay_bundle
from tools.safe_lab.build_attack_test_bundle import _build_events


def test_attack_bundle_has_benign_and_attack_metadata(tmp_path):
    events = _build_events(42)
    result = write_replay_bundle(events, tmp_path, "attack_signatures", 42)
    manifest = result["manifest"]

    assert manifest["event_count"] == len(events)
    assert manifest["is_synthetic"] is True
    assert manifest["is_executable"] is False
    assert manifest["payload_decrypted"] is False
    assert {event["_ground_truth"]["label"] for event in events} == {"benign", "attack"}
    assert all(next(iter_analyzer_events(path, max_records=1))["type"] == "flow" for path in result["outputs"])


def test_bundle_csv_preserves_dns_records(tmp_path):
    events = _build_events(7)
    result = write_replay_bundle(events, tmp_path, "attack_signatures", 7)
    csv_path = next(path for path in result["outputs"] if path.endswith(".csv"))
    parsed = list(iter_analyzer_events(csv_path, max_records=10_000))

    assert len(parsed) == len(events)
    assert any(event["type"] == "dns" for event in parsed)
    assert all("payload" not in json.dumps(event).lower() for event in parsed)
