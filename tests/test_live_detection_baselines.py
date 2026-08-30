"""Regression tests for safe live-mode fallbacks and the trusted artifact."""

from netsentinel.detectors.beaconing import BeaconingRuleDetector
from netsentinel.detectors.dns_anomaly import DNSAnomalyRuleDetector
from netsentinel.detectors.volumetric import VolumetricFloodRuleDetector


def test_volumetric_baseline_requires_rate_and_handshake_signals():
    result = VolumetricFloodRuleDetector().predict({"features": {
        "Flow Packets/s": 75_000,
        "Flow Bytes/s": 8_000_000,
        "SYN Flag Count": 1,
        "ACK Flag Count": 0,
        "Protocol": 6,
    }})
    assert result["triggered"] is True
    assert result["threat"] == "DDoS"


def test_dns_baseline_flags_high_entropy_label_without_payload():
    result = DNSAnomalyRuleDetector().predict("q7m2k9x4p8v1z6.info")
    assert result["is_malicious"] is True
    assert result["threat"] == "DGA"


def test_beacon_baseline_flags_low_variance_inter_arrivals():
    result = BeaconingRuleDetector().predict([{"iat": 60 + (index % 2) * 0.5} for index in range(12)])
    assert result["is_beacon"] is True
    assert result["threat"] == "C2 Beacon"
