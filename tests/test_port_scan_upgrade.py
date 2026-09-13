from netsentinel.detectors.reconnaissance import ReconnaissanceRuleDetector


def test_mixed_host_and_service_scan_is_classified():
    pairs = {(f"10.0.1.{host}", port) for host in range(12) for port in (22, 80, 443)}
    result = ReconnaissanceRuleDetector().predict(
        {
            "features": {
                "SYN Flag Count": 1,
                "ACK Flag Count": 0,
                "Fwd Packets Length Total": 80,
                "Total Fwd Packets": 2,
            }
        },
        {
            "destinations": {host for host, _ in pairs},
            "ports": {port for _, port in pairs},
            "destination_port_pairs": pairs,
            "flows": len(pairs),
            "first_seen": 100.0,
            "last_seen": 160.0,
        },
    )

    assert result["triggered"] is True
    assert result["subtype"] == "Mixed Host and Service Scan"
    assert result["feature_snapshot"]["unique_target_port_pairs"] == len(pairs)
    assert result["feature_snapshot"]["probes_per_minute"] == len(pairs)