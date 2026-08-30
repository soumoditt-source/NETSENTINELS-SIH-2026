from addons.netsentinel_plus.assessment import build_temporal_assessment


def _base(telemetry=None, alerts=None):
    return build_temporal_assessment(
        telemetry=telemetry or {},
        alerts=alerts or [],
        health={"read_only_mode": True, "payload_decrypted": False, "models": {"models_loaded": {"c2": True}}},
        launch_report={"real_data": {"dataset": "CIC-IDS2017", "status": "measured_real_data"}},
    )


def test_empty_window_does_not_assert_an_alert():
    result = _base({"events_in_window": 0, "alerts_in_window": 0, "read_only": True})
    assert result["state"] == "NO_CURRENT_SIGNAL"
    assert result["triage_score"] == 0.0
    assert result["detector_score_unchanged"] is True


def test_independent_temporal_evidence_prioritizes_review():
    result = _base(
        {
            "events_in_window": 40,
            "alerts_in_window": 3,
            "read_only": True,
            "temporal_features": {
                "inter_arrival_cv": 0.04,
                "unique_destination_ports": 35,
                "burst_ratio": 5.2,
                "outbound_inbound_ratio": 12.0,
                "destination_concentration": 0.91,
                "dns_anomaly_score": 0.88,
            },
        },
        [
            {"detector": "c2_beacon", "threat_class": "C2 Beacon", "confidence": 0.91},
            {"detector": "reconnaissance", "threat_class": "Port Scan", "confidence": 0.83},
        ],
    )
    assert result["state"] == "CORRELATED_REVIEW"
    assert result["triage_score"] >= 70
    assert len(result["independent_evidence"]["temporal_signals"]) == 4
    assert len(result["independent_evidence"]["c2_signals"]) == 2


def test_single_signal_is_bounded_and_not_relabelled():
    result = _base(
        {"events_in_window": 1, "alerts_in_window": 1, "read_only": True},
        [{"detector": "unknown", "threat_class": "Unknown", "confidence": 0.99}],
    )
    assert result["state"] == "SINGLE_SIGNAL_REVIEW"
    assert result["triage_score"] < 60
    assert result["score_type"] == "analyst_prioritization_not_detector_confidence"
