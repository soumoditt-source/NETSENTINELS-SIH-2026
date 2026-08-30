"""Deterministic temporal evidence convergence for analyst triage."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any


ASSESSMENT_VERSION = "tec-1.0"
_TEMPORAL_CHECKS = (
    ("periodicity", "inter_arrival_cv", "<=", 0.15, "regular inter-arrival timing"),
    ("port_fanout", "unique_destination_ports", ">=", 20.0, "destination-port fan-out"),
    ("bursting", "burst_ratio", ">=", 3.0, "traffic burst above the local mean"),
    ("byte_asymmetry", "outbound_inbound_ratio", ">=", 10.0, "outbound-to-inbound byte asymmetry"),
)
_C2_CHECKS = (
    ("destination_concentration", "destination_concentration", ">=", 0.70, "repeated contact with a concentrated destination set"),
    ("dns_precursor", "dns_anomaly_score", ">=", 0.70, "DNS anomaly precedes the session pattern"),
    ("rare_tls_fingerprint", "tls_fingerprint_rarity", ">=", 0.70, "uncommon TLS fingerprint metadata"),
    ("small_repeated_flows", "mean_bytes_per_flow", "<=", 2048.0, "small repeated flows consistent with check-ins"),
)


def build_temporal_assessment(
    *,
    telemetry: Mapping[str, Any] | None,
    alerts: Iterable[Mapping[str, Any]] | None,
    health: Mapping[str, Any] | None,
    launch_report: Mapping[str, Any] | None,
) -> dict[str, Any]:
    telemetry_data = _mapping(telemetry)
    health_data = _mapping(health)
    report_data = _mapping(launch_report)
    feature_data = _mapping(telemetry_data.get("temporal_features"))
    alert_items = [dict(item) for item in (alerts or ()) if isinstance(item, Mapping)]
    feature_data = _merge_features(feature_data, alert_items)

    detectors = sorted({name for item in alert_items if (name := _label(item.get("detector")))})
    threat_classes = sorted({name for item in alert_items if (name := _label(item.get("threat_class")))})
    confidences = [_clamp(_number(item.get("confidence")), 0.0, 1.0) for item in alert_items]
    maximum_confidence = max(confidences, default=0.0)
    event_count = max(0, _integer(telemetry_data.get("events_in_window")))
    reported_alerts = max(0, _integer(telemetry_data.get("alerts_in_window")))
    alert_count = max(len(alert_items), reported_alerts)
    temporal_signals = _temporal_signals(feature_data, event_count)
    c2_signals = _c2_signals(feature_data, event_count)

    signal_strength = maximum_confidence
    detector_diversity = _clamp(len(detectors) / 3.0, 0.0, 1.0)
    recurrence = _clamp(alert_count / 5.0, 0.0, 1.0)
    temporal_context = _clamp((len(temporal_signals) + len(c2_signals)) / 4.0, 0.0, 1.0)
    triage_score = round(
        100.0 * (
            0.45 * signal_strength
            + 0.25 * detector_diversity
            + 0.15 * recurrence
            + 0.15 * temporal_context
        ),
        1,
    ) if alert_count else 0.0

    if not alert_count and not event_count:
        state = "NO_CURRENT_SIGNAL"
        band = "insufficient_evidence"
    elif not alert_count:
        state = "OBSERVING"
        band = "telemetry_only"
    elif detector_diversity >= 2 / 3 and triage_score >= 70:
        state = "CORRELATED_REVIEW"
        band = "high_convergence"
    elif triage_score >= 60:
        state = "PRIORITIZED_REVIEW"
        band = "multi_signal" if detector_diversity > 1 / 3 else "single_signal"
    else:
        state = "SINGLE_SIGNAL_REVIEW"
        band = "single_signal"

    models = _mapping(_mapping(health_data.get("models")).get("models_loaded"))
    real_data = _mapping(report_data.get("real_data"))
    safety_read_only = health_data.get("read_only_mode") is True and telemetry_data.get("read_only") is True
    payload_decrypted = health_data.get("payload_decrypted") is True or telemetry_data.get("payload_decrypted") is True

    return {
        "assessment_version": ASSESSMENT_VERSION,
        "state": state,
        "band": band,
        "triage_score": triage_score,
        "score_type": "analyst_prioritization_not_detector_confidence",
        "detector_score_unchanged": True,
        "formula": {
            "signal_strength": round(signal_strength, 4),
            "detector_diversity": round(detector_diversity, 4),
            "recurrence": round(recurrence, 4),
            "temporal_context": round(temporal_context, 4),
            "weights": {"signal_strength": 0.45, "detector_diversity": 0.25, "recurrence": 0.15, "temporal_context": 0.15},
        },
        "independent_evidence": {
            "detectors": detectors,
            "threat_classes": threat_classes,
            "temporal_signals": temporal_signals,
            "c2_signals": c2_signals,
            "specialization": "metadata-only C2 behavior convergence",
            "counts": {"alerts": alert_count, "events": event_count, "detectors": len(detectors)},
        },
        "observation": {
            "state": "populated_window" if event_count else "empty_window",
            "window_seconds": max(0, _integer(telemetry_data.get("window_seconds"))),
            "events_in_window": event_count,
            "last_event_at": telemetry_data.get("last_event_at"),
            "bounded_store": _mapping(telemetry_data.get("bounded_store")),
        },
        "provenance": {
            "dataset": real_data.get("dataset"),
            "launch_report_status": real_data.get("status"),
            "loaded_model_count": sum(value is True for value in models.values()),
            "read_only": safety_read_only,
            "payload_decrypted": payload_decrypted,
        },
        "safe_next_step": _next_step(state),
    }


def _temporal_signals(features: Mapping[str, Any], event_count: int) -> list[dict[str, Any]]:
    signals: list[dict[str, Any]] = []
    for name, feature, operator, threshold, description in _TEMPORAL_CHECKS:
        if feature not in features:
            continue
        observed = _number(features.get(feature))
        if name == "periodicity" and event_count < 4:
            continue
        triggered = observed <= threshold if operator == "<=" else observed >= threshold
        if triggered:
            signals.append({"signal": name, "feature": feature, "observed": round(observed, 4), "rule": f"{operator} {threshold:g}", "description": description})
    return signals


def _c2_signals(features: Mapping[str, Any], event_count: int) -> list[dict[str, Any]]:
    signals: list[dict[str, Any]] = []
    if event_count < 4:
        return signals
    for name, feature, operator, threshold, description in _C2_CHECKS:
        if feature not in features:
            continue
        observed = _number(features.get(feature))
        triggered = observed <= threshold if operator == "<=" else observed >= threshold
        if triggered:
            signals.append({"signal": name, "feature": feature, "observed": round(observed, 4), "rule": f"{operator} {threshold:g}", "description": description})
    return signals


def _merge_features(base: Mapping[str, Any], alerts: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    merged = dict(base)
    for alert in alerts:
        snapshot = _mapping(alert.get("feature_snapshot"))
        for key, value in snapshot.items():
            if key not in merged and isinstance(value, (bool, int, float)):
                merged[key] = value
    return merged


def _next_step(state: str) -> str:
    if state == "NO_CURRENT_SIGNAL":
        return "Continue bounded observation; no alert is asserted."
    if state == "OBSERVING":
        return "Retain the metadata window and wait for independent evidence."
    return "Review the correlated metadata case in the authorized SOC workflow; do not block from this score."


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _label(value: Any) -> str:
    return str(value).strip()[:120] if value is not None and str(value).strip() else ""


def _number(value: Any) -> float:
    try:
        result = float(value)
    except (TypeError, ValueError):
        return 0.0
    return result if result == result else 0.0


def _integer(value: Any) -> int:
    return int(_number(value))


def _clamp(value: float, lower: float, upper: float) -> float:
    return max(lower, min(upper, value))
