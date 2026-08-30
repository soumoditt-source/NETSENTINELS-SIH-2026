"""Regression tests for narrow, non-enforcing alert guidance."""

from netsentinel.pipeline.alert_manager import AlertManager


def test_port_scan_scope_targets_source_not_whole_network():
    alert = AlertManager().create_alert({"threat": "Port Scan", "confidence": 0.9, "model": "test"})

    assert alert["containment_scope"]["scope_type"] == "source_identity"
    assert alert["containment_scope"]["automatic_enforcement"] is False


def test_exfiltration_scope_targets_flow_pair():
    alert = AlertManager().create_alert({"threat": "Data Exfiltration", "confidence": 0.9, "model": "test"})

    assert alert["containment_scope"]["scope_type"] == "source_to_destination_pair"
    assert "approved egress controls" in alert["containment_scope"]["recommended_action"]
