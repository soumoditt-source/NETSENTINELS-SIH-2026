"""Tests for bounded metadata-only evidence replay support."""

from __future__ import annotations

import pytest

from netsentinel.forensics.temporal import TemporalForensics
from netsentinel.ingest.flow_adapter import iter_analyzer_events, validate_metadata_record


def test_temporal_summary_is_bounded_and_payload_free():
    store = TemporalForensics(window_seconds=300, max_events=2)
    for index in range(3):
        store.observe({
            "type": "flow",
            "observed_at": 1_700_000_000 + index,
            "source_ip": f"192.0.2.{index + 1}",
            "dest_ip": "198.51.100.10",
            "features": {"Protocol": 6, "Total Fwd Packets": 2, "Fwd Packets Length Total": 120},
        })
    summary = store.summary()
    assert summary["events_in_window"] == 2
    assert summary["bounded_store"]["max_events"] == 2
    assert summary["metadata_only"] is True
    assert "payload" not in summary


def test_metadata_validator_rejects_payload_fields():
    with pytest.raises(ValueError, match="forbidden payload field"):
        validate_metadata_record({"type": "flow", "payload": "not accepted"}, 1)


def test_safe_fixture_is_readable_as_analyzer_events():
    path = "data/processed/safe_lab/hard_negative_legitimate_service_42.jsonl"
    event = next(iter_analyzer_events(path, max_records=1))
    assert event["type"] == "flow"
    assert event["features"]["Destination Port"] == 443
