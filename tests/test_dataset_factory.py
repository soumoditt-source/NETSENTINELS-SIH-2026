"""Focused tests for local data preparation and safe replay contracts."""

from __future__ import annotations

import json

import pandas as pd

from netsentinel.data.schemas import CanonicalFlowEvent
from netsentinel.simulator.safe_scenarios import benign_web_browsing
from netsentinel.simulator.safe_trace_writer import write_replay_bundle
from tools.datasets.cicids2017_factory import prepare_cicids2017


def _write_cic_csv(path, label: str) -> None:
    pd.DataFrame([
        {
            "Flow ID": f"flow-{label}",
            "Source IP": "192.168.10.10",
            "Destination IP": "192.168.10.20",
            "Destination Port": 443,
            "Flow Duration": 1000,
            "Total Fwd Packets": 4,
            "Total Length of Fwd Packets": 800,
            "Total Length of Bwd Packets": 1200,
            "Label": label,
            "Timestamp": "2017-07-03 09:00:00",
        }
    ]).to_csv(path, index=False)


def test_cicids_factory_writes_canonical_outputs(tmp_path):
    raw = tmp_path / "raw"
    raw.mkdir()
    _write_cic_csv(raw / "Monday.csv", "BENIGN")
    _write_cic_csv(raw / "Tuesday.csv", "PortScan")
    result = prepare_cicids2017(raw, tmp_path / "data", export_csv=True)
    assert (tmp_path / "data/processed/canonical/cicids2017_flows.parquet").is_file()
    assert (tmp_path / "data/processed/test/cicids2017_test.parquet").is_file()
    manifest = json.loads((tmp_path / "data/artifacts/manifests/cicids2017_manifest.json").read_text())
    assert manifest["label_distribution"] == {"benign": 1, "reconnaissance": 1}
    assert result["split_manifest"]["method"] == "ordered_fallback_without_timestamp"


def test_canonical_flow_rejects_invalid_port():
    event = CanonicalFlowEvent(
        event_id="e1",
        flow_id="f1",
        src_identity="anon_a",
        dst_identity="anon_b",
        src_port=1,
        dst_port=443,
        protocol="tcp",
    )
    assert event.schema_version == "1.0.0"


def test_safe_bundle_is_reproducible_and_metadata_only(tmp_path):
    first = write_replay_bundle(benign_web_browsing(seed=4, n=2), tmp_path / "first", "web", 4)
    second = write_replay_bundle(benign_web_browsing(seed=4, n=2), tmp_path / "second", "web", 4)
    first_lines = (tmp_path / "first/web_4.jsonl").read_text()
    second_lines = (tmp_path / "second/web_4.jsonl").read_text()
    assert first_lines == second_lines
    assert first["manifest"]["is_synthetic"] is True
    assert second["manifest"]["payload_decrypted"] is False
