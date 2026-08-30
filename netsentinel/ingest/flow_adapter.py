"""Read normalized CSV, JSONL, and Parquet flow records incrementally."""

from __future__ import annotations

import csv
import json
import math
from pathlib import Path
from typing import Any, Iterator

from .normalized_event import NormalizedEvent


def _number(value: Any, default: float = 0.0) -> float:
    """Convert nullable source values without allowing NaN into the schema."""

    try:
        result = float(value)
        return result if result == result else default
    except (TypeError, ValueError):
        return default


FORBIDDEN_METADATA_KEYS = {
    "payload", "raw_payload", "payload_bytes", "content", "decrypted_content",
    "credential", "credentials", "password", "secret", "token", "command",
    "script", "executable", "shell", "webhook",
}


def validate_metadata_record(record: Any, record_number: int = 0) -> dict[str, Any]:
    """Reject payload-bearing records before they enter the analyzer."""
    if not isinstance(record, dict):
        raise ValueError(f"Record {record_number} is not an object")

    def walk(value: Any, depth: int = 0) -> None:
        if depth > 6:
            raise ValueError(f"Record {record_number} exceeds metadata nesting limit")
        if isinstance(value, dict):
            for key, child in value.items():
                normalized = str(key).strip().lower().replace("-", "_")
                if normalized in FORBIDDEN_METADATA_KEYS:
                    raise ValueError(f"Record {record_number} contains forbidden payload field '{key}'")
                walk(child, depth + 1)
        elif isinstance(value, list):
            if len(value) > 10_000:
                raise ValueError(f"Record {record_number} contains an oversized metadata list")
            for child in value:
                walk(child, depth + 1)
        elif isinstance(value, str) and len(value) > 16_384:
            raise ValueError(f"Record {record_number} contains an oversized metadata string")

    walk(record)
    return record


def _event(record: dict[str, Any], source_type: str) -> NormalizedEvent:
    """Convert common normalized flow field names into one event contract."""

    lowered = {str(key).strip().lower(): value for key, value in record.items()}
    source = lowered.get("source_ip", lowered.get("src_ip", lowered.get("source ip", lowered.get("source_identity", "unknown"))))
    destination = lowered.get("dest_ip", lowered.get("dst_ip", lowered.get("destination ip", lowered.get("destination_identity", "unknown"))))
    raw_features = record.get("features", {})
    features = dict(raw_features) if isinstance(raw_features, dict) else {}
    feature_names = {
        "destination port": "Destination Port",
        "protocol": "Protocol",
        "total fwd packets": "Total Fwd Packets",
        "total backward packets": "Total Backward Packets",
        "fwd packets length total": "Fwd Packets Length Total",
        "bwd packets length total": "Bwd Packets Length Total",
        "flow bytes/s": "Flow Bytes/s",
        "flow packets/s": "Flow Packets/s",
        "syn flag count": "SYN Flag Count",
        "ack flag count": "ACK Flag Count",
        "avg fwd segment size": "Avg Fwd Segment Size",
    }
    for key, value in lowered.items():
        if key in feature_names and key not in {"source_ip", "dest_ip"}:
            numeric = _number(value, math.nan)
            if math.isfinite(numeric):
                features[feature_names[key]] = numeric
                features[key] = numeric
    fwd_packets = _number(lowered.get("fwd_packets", features.get("Total Fwd Packets")))
    rev_packets = _number(lowered.get("rev_packets", features.get("Total Backward Packets")))
    fwd_bytes = _number(lowered.get("fwd_bytes", features.get("Fwd Packets Length Total")))
    rev_bytes = _number(lowered.get("rev_bytes", features.get("Bwd Packets Length Total")))
    first_seen = _number(lowered.get("first_seen", lowered.get("observed_at")))
    last_seen = _number(lowered.get("last_seen", first_seen + _number(lowered.get("duration"))))
    protocol = lowered.get("protocol", features.get("Protocol", "unknown"))
    try:
        protocol = int(float(protocol))
    except (TypeError, ValueError):
        protocol = str(protocol)
    return NormalizedEvent(
        source_type=source_type,
        flow_id=str(lowered.get("flow_id", lowered.get("event_id", "unknown"))),
        src_ip=str(source),
        dst_ip=str(destination),
        src_port=int(_number(lowered.get("src_port", lowered.get("source_port", 0)), 0)),
        dst_port=int(_number(lowered.get("dst_port", lowered.get("destination port", lowered.get("dest_port", 0))), 0)),
        protocol=str(protocol),
        direction=str(lowered.get("direction", "unknown")),
        packets=int(fwd_packets + rev_packets),
        bytes=int(fwd_bytes + rev_bytes),
        duration=max(0.0, last_seen - first_seen),
        first_seen=first_seen,
        last_seen=last_seen,
        tcp_flags=lowered.get("tcp_flags"),
        dns_metadata=lowered.get("dns_metadata"),
        tls_metadata=lowered.get("tls_metadata"),
        quic_metadata=lowered.get("quic_metadata"),
        service_label=lowered.get("service_label"),
        raw_reference={"source_type": source_type, "field_count": len(record)},
    )


def normalized_to_analyzer_event(event: NormalizedEvent) -> dict[str, Any]:
    """Bridge the canonical event contract to the streaming analyzer contract."""
    features = {
        "Destination Port": event.dst_port,
        "Protocol": int(event.protocol) if str(event.protocol).isdigit() else event.protocol,
        "Total Fwd Packets": event.packets,
        "Total Backward Packets": 0,
        "Fwd Packets Length Total": event.bytes,
        "Bwd Packets Length Total": 0,
        "Flow Packets/s": event.packets / max(event.duration, 1e-9),
        "Flow Bytes/s": event.bytes / max(event.duration, 1e-9),
    }
    return {
        "type": "flow",
        "event_id": event.event_id,
        "observed_at": event.observed_at,
        "flow_id": event.flow_id,
        "source_ip": event.src_ip,
        "dest_ip": event.dst_ip,
        "direction": event.direction,
        "features": features,
        "service_label": event.service_label,
    }


def _prepare_record(record: dict[str, Any], record_number: int) -> dict[str, Any]:
    """Normalize safe fixture JSON while preserving only analysis metadata."""
    validate_metadata_record(record, record_number)
    prepared = dict(record)
    numeric_fields = {
        "observed_at", "first_seen", "last_seen", "duration", "_bytes_out", "_bytes_in",
        "src_port", "dst_port", "source_port", "destination_port", "fwd_packets", "rev_packets",
        "fwd_bytes", "rev_bytes",
    }
    integer_fields = {"src_port", "dst_port", "source_port", "destination_port", "fwd_packets", "rev_packets"}
    for key in numeric_fields:
        value = prepared.get(key)
        if value is None or (isinstance(value, float) and math.isnan(value)):
            prepared.pop(key, None)
            continue
        if isinstance(value, str):
            if not value.strip():
                prepared.pop(key, None)
                continue
            try:
                prepared[key] = int(float(value)) if key in integer_fields else float(value)
            except ValueError as exc:
                raise ValueError(f"Record {record_number} has invalid numeric field '{key}'") from exc
    for key, value in list(prepared.items()):
        if value is None and key not in {"features_json", "flows_json"}:
            prepared.pop(key)
    if isinstance(prepared.get("features_json"), str):
        try:
            features = json.loads(prepared["features_json"])
        except json.JSONDecodeError as exc:
            raise ValueError(f"Record {record_number} has malformed features_json") from exc
        if not isinstance(features, dict):
            raise ValueError(f"Record {record_number} features_json is not an object")
        prepared["features"] = features
    if isinstance(prepared.get("flows_json"), str):
        try:
            flows = json.loads(prepared["flows_json"])
        except json.JSONDecodeError as exc:
            raise ValueError(f"Record {record_number} has malformed flows_json") from exc
        if not isinstance(flows, list):
            raise ValueError(f"Record {record_number} flows_json is not a list")
        prepared["flows"] = flows
    return prepared


def iter_analyzer_events(filepath: str | Path, max_records: int = 20_000) -> Iterator[dict[str, Any]]:
    """Yield bounded, metadata-only events from JSONL, CSV, or Parquet."""
    path = Path(filepath).resolve()
    if not path.is_file():
        raise FileNotFoundError(path)
    if max_records < 1:
        raise ValueError("max_records must be positive")
    suffix = path.suffix.lower()
    count = 0
    if suffix in {".jsonl", ".ndjson"}:
        with path.open("r", encoding="utf-8-sig") as handle:
            for line_number, line in enumerate(handle, 1):
                if not line.strip():
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise ValueError(f"Malformed JSON on line {line_number} of {path.name}") from exc
                prepared = _prepare_record(record, line_number)
                if prepared.get("type") in {"dns", "session", "flow"}:
                    yield prepared
                else:
                    yield normalized_to_analyzer_event(_event(prepared, "netflow"))
                count += 1
                if count >= max_records:
                    return
        return
    if suffix == ".csv":
        with path.open("r", encoding="utf-8-sig", newline="") as handle:
            for row_number, row in enumerate(csv.DictReader(handle), 2):
                prepared = _prepare_record(row, row_number)
                if prepared.get("type") in {"dns", "session", "flow"}:
                    yield prepared
                else:
                    yield normalized_to_analyzer_event(_event(prepared, "netflow"))
                count += 1
                if count >= max_records:
                    return
        return
    if suffix == ".parquet":
        import pandas as pd

        frame = pd.read_parquet(path)
        for row_number, record in enumerate(frame.to_dict(orient="records"), 1):
            prepared = _prepare_record(record, row_number)
            if prepared.get("type") in {"dns", "session", "flow"}:
                yield prepared
            else:
                yield normalized_to_analyzer_event(_event(prepared, "netflow"))
            count += 1
            if count >= max_records:
                return
        return
    raise ValueError("Only .jsonl, .ndjson, .csv, and .parquet metadata files are supported")


def iter_flow_records(filepath: str | Path) -> Iterator[NormalizedEvent]:
    """Yield records from CSV, JSONL, or Parquet without executing source data."""

    path = Path(filepath).resolve()
    if not path.is_file():
        raise FileNotFoundError(path)
    suffix = path.suffix.lower()
    if suffix == ".csv":
        with path.open("r", encoding="utf-8-sig", newline="") as handle:
            yield from (_event(row, "netflow") for row in csv.DictReader(handle))
        return
    if suffix in {".jsonl", ".ndjson"}:
        with path.open("r", encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, 1):
                if not line.strip():
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise ValueError(f"Malformed JSON on line {line_number} of {path.name}") from exc
                if not isinstance(record, dict):
                    raise ValueError(f"JSONL record {line_number} is not an object")
                yield _event(record, "netflow" if record.get("source_type") != "simulator" else "simulator")
        return
    if suffix == ".parquet":
        import pandas as pd

        frame = pd.read_parquet(path)
        for record in frame.to_dict(orient="records"):
            yield _event(record, "netflow")
        return
    raise ValueError(f"Unsupported flow file type: {suffix}")
