"""Bounded temporal summaries for read-only network forensics.

The store intentionally keeps aggregate metadata only. It never retains packet
payloads, decrypted content, credentials, or arbitrary uploaded record bodies.
"""

from __future__ import annotations

import math
import time
from collections import Counter, deque
from datetime import datetime
from typing import Any


def _number(value: Any, default: float = 0.0) -> float:
    try:
        number = float(value)
        return number if math.isfinite(number) else default
    except (TypeError, ValueError):
        return default


def _timestamp(value: Any) -> float:
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
        except ValueError:
            return time.time()
    return _number(value, time.time())


class TemporalForensics:
    """Maintain a bounded sliding window of flow/session metadata."""

    def __init__(self, window_seconds: float = 300.0, max_events: int = 50_000) -> None:
        self.window_seconds = window_seconds
        self.events: deque[dict[str, Any]] = deque(maxlen=max_events)
        self.alerts: deque[dict[str, Any]] = deque(maxlen=max_events)
        self.total_events = 0
        self._latest_event_timestamp = 0.0

    def observe(self, event: dict[str, Any]) -> None:
        """Record only fields needed for temporal aggregates."""
        features = event.get("features", {}) if isinstance(event.get("features"), dict) else {}
        fwd_packets = _number(features.get("Total Fwd Packets", 0))
        back_packets = _number(features.get("Total Backward Packets", 0))
        fwd_bytes = _number(features.get("Fwd Packets Length Total", 0))
        back_bytes = _number(features.get("Bwd Packets Length Total", 0))
        packets = _number(event.get("packets", fwd_packets + back_packets))
        bytes_seen = _number(event.get("bytes", fwd_bytes + back_bytes))
        port = _number(features.get("Destination Port", features.get("destination port", 0)))
        protocol = event.get("protocol", features.get("Protocol", features.get("protocol", "unknown")))
        direction = str(event.get("direction", "outbound"))
        outbound_default = fwd_bytes if direction != "inbound" else back_bytes
        inbound_default = back_bytes if direction != "inbound" else fwd_bytes
        event_timestamp = _timestamp(event.get("observed_at", event.get("timestamp")))
        self._latest_event_timestamp = max(self._latest_event_timestamp, event_timestamp)
        self.events.append({
            "timestamp": event_timestamp,
            "event_type": str(event.get("type", "flow")),
            "source": str(event.get("source_ip", event.get("src_ip", "unknown"))),
            "destination": str(event.get("dest_ip", event.get("dst_ip", "unknown"))),
            "protocol": str(protocol),
            "port": int(port) if port.is_integer() and port >= 0 else 0,
            "syn": _number(features.get("SYN Flag Count", features.get("syn flag count", 0))),
            "ack": _number(features.get("ACK Flag Count", features.get("ack flag count", 0))),
            "direction": direction,
            "outbound_bytes": _number(event.get("_bytes_out", outbound_default)),
            "inbound_bytes": _number(event.get("_bytes_in", inbound_default)),
            "packets": max(0.0, packets),
            "bytes": max(0.0, bytes_seen),
        })
        self.total_events += 1

    def record_alert(self, alert: dict[str, Any], observed_at: Any = None) -> None:
        """Record alert metadata without copying its evidence payload."""
        self.alerts.append({
            "timestamp": _timestamp(observed_at if observed_at is not None else alert.get("timestamp")),
            "threat_class": str(alert.get("threat_class", "Unknown")),
            "severity": str(alert.get("severity", "UNKNOWN")),
            "confidence": _number(alert.get("confidence")),
        })

    def summary(self) -> dict[str, Any]:
        latest = self._latest_event_timestamp or time.time()
        cutoff = latest - self.window_seconds
        rows = [row for row in self.events if row["timestamp"] >= cutoff]
        alert_rows = [row for row in self.alerts if row["timestamp"] >= cutoff]
        timestamps = [row["timestamp"] for row in rows]
        span = min(self.window_seconds, max(timestamps) - min(timestamps)) if len(timestamps) > 1 else 0.0
        rate_window = max(span, 1.0)
        sources = Counter(row["source"] for row in rows)
        destinations = Counter(row["destination"] for row in rows)
        ports = Counter(row["port"] for row in rows if row["port"] > 0)
        protocols = Counter(row["protocol"] for row in rows)
        event_types = Counter(row["event_type"] for row in rows)
        alert_classes = Counter(row["threat_class"] for row in alert_rows)
        intervals = [right - left for left, right in zip(sorted(timestamps), sorted(timestamps)[1:]) if right > left]
        interval_mean = sum(intervals) / len(intervals) if intervals else 0.0
        interval_std = math.sqrt(sum((value - interval_mean) ** 2 for value in intervals) / len(intervals)) if intervals else 0.0
        source_entropy = self._entropy(sources)
        destination_entropy = self._entropy(destinations)
        syn = sum(row["syn"] for row in rows)
        ack = sum(row["ack"] for row in rows)
        outbound = sum(row["outbound_bytes"] for row in rows)
        inbound = sum(row["inbound_bytes"] for row in rows)
        bucket_width = self.window_seconds / 12
        timeline = [{"bucket": index, "events": 0, "packets": 0.0, "bytes": 0.0} for index in range(12)]
        for row in rows:
            index = min(11, max(0, int((row["timestamp"] - cutoff) / max(bucket_width, 1))))
            timeline[index]["events"] += 1
            timeline[index]["packets"] += row["packets"]
            timeline[index]["bytes"] += row["bytes"]
        average_bucket_events = len(rows) / 12 if rows else 0.0
        peak_bucket_events = max((bucket["events"] for bucket in timeline), default=0)
        return {
            "window_seconds": self.window_seconds,
            "events_in_window": len(rows),
            "total_events_observed": self.total_events,
            "first_event_at": min(timestamps) if timestamps else None,
            "last_event_at": max(timestamps) if timestamps else None,
            "flows_per_second": round(len(rows) / rate_window, 3),
            "packets_per_second": round(sum(row["packets"] for row in rows) / rate_window, 3),
            "bytes_per_second": round(sum(row["bytes"] for row in rows) / rate_window, 3),
            "unique_sources": len(sources),
            "unique_destinations": len(destinations),
            "top_sources": [{"value": value, "count": count} for value, count in sources.most_common(5)],
            "top_destinations": [{"value": value, "count": count} for value, count in destinations.most_common(5)],
            "top_ports": [{"value": value, "count": count} for value, count in ports.most_common(8)],
            "protocols": dict(protocols),
            "event_types": dict(event_types),
            "alerts_in_window": len(alert_rows),
            "alert_classes": dict(alert_classes),
            "timeline": timeline,
            "temporal_features": {
                "inter_arrival_mean_seconds": round(interval_mean, 3),
                "inter_arrival_cv": round(interval_std / max(interval_mean, 1e-9), 3),
                "source_entropy_bits": round(source_entropy, 3),
                "destination_entropy_bits": round(destination_entropy, 3),
                "unique_destination_ports": len(ports),
                "syn_ack_ratio": round(syn / max(ack, 1.0), 3),
                "outbound_inbound_ratio": round(outbound / max(inbound, 1.0), 3),
                "burst_ratio": round(peak_bucket_events / max(average_bucket_events, 1.0), 3),
            },
            "bounded_store": {"max_events": self.events.maxlen, "max_alerts": self.alerts.maxlen},
            "metadata_only": True,
            "read_only": True,
        }

    @staticmethod
    def _entropy(counter: Counter) -> float:
        total = sum(counter.values())
        if not total:
            return 0.0
        return -sum((count / total) * math.log2(count / total) for count in counter.values())
