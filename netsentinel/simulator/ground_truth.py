"""
netsentinel/simulator/ground_truth.py
======================================
Ground-truth tracker for replay evaluation.

Records both the ground-truth labels emitted by safe_scenarios and
the detector outputs. Computes precision/recall/F1 per scenario.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any
import time


@dataclass
class GroundTruthRecord:
    event_id: str
    observed_at: float
    ground_truth_label: str          # "benign" | "attack"
    ground_truth_scenario: str
    threat_class_expected: str = ""
    detector_output_label: str = ""  # "benign" | "attack"
    detector_threat_class: str = ""
    detector_confidence: float = 0.0
    detector_name: str = ""
    was_missed: bool = False
    was_false_positive: bool = False
    detection_latency_ms: float = 0.0


class GroundTruthTracker:
    """
    Compares ground-truth labels from safe scenarios against detector output.
    Produces honest precision/recall/F1 per threat class.
    """

    def __init__(self) -> None:
        self._records: list[GroundTruthRecord] = []
        self._emit_time: dict[str, float] = {}

    def record_emit(self, event_id: str, ground_truth: dict[str, Any]) -> None:
        """Call when a scenario event is emitted."""
        self._emit_time[event_id] = time.time()
        self._records.append(GroundTruthRecord(
            event_id=event_id,
            observed_at=time.time(),
            ground_truth_label=ground_truth.get("label", "benign"),
            ground_truth_scenario=ground_truth.get("scenario", "unknown"),
            threat_class_expected=ground_truth.get("threat_class", ""),
        ))

    def record_detection(self, event_id: str, alert: dict[str, Any] | None) -> None:
        """Call when the detector pipeline produces (or doesn't produce) an alert."""
        rec = next((r for r in self._records if r.event_id == event_id), None)
        if rec is None:
            return
        emit_t = self._emit_time.get(event_id, time.time())
        rec.detection_latency_ms = (time.time() - emit_t) * 1000

        if alert:
            rec.detector_output_label = "attack"
            rec.detector_threat_class = alert.get("threat_class", "")
            rec.detector_confidence = alert.get("confidence", 0.0)
            rec.detector_name = alert.get("detector", "")
            if rec.ground_truth_label == "benign":
                rec.was_false_positive = True
        else:
            rec.detector_output_label = "benign"
            if rec.ground_truth_label == "attack":
                rec.was_missed = True

    def compute_metrics(self) -> dict[str, Any]:
        """Return precision, recall, F1, FP/FN counts, and per-class breakdown."""
        tp = sum(1 for r in self._records
                 if r.ground_truth_label == "attack" and r.detector_output_label == "attack")
        fp = sum(1 for r in self._records if r.was_false_positive)
        fn = sum(1 for r in self._records if r.was_missed)
        tn = sum(1 for r in self._records
                 if r.ground_truth_label == "benign" and r.detector_output_label == "benign")

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0

        latencies = [r.detection_latency_ms for r in self._records
                     if r.detector_output_label == "attack"]
        latencies.sort()

        def percentile(lst: list[float], p: float) -> float:
            if not lst:
                return 0.0
            idx = int(len(lst) * p / 100)
            return lst[min(idx, len(lst) - 1)]

        # Per-class breakdown
        classes: dict[str, dict] = {}
        for r in self._records:
            tc = r.threat_class_expected or "benign"
            if tc not in classes:
                classes[tc] = {"tp": 0, "fp": 0, "fn": 0, "tn": 0}
            if r.ground_truth_label == "attack":
                if r.detector_output_label == "attack":
                    classes[tc]["tp"] += 1
                else:
                    classes[tc]["fn"] += 1
            else:
                if r.detector_output_label == "attack":
                    classes[tc]["fp"] += 1
                else:
                    classes[tc]["tn"] += 1

        return {
            "total_events": len(self._records),
            "true_positives": tp,
            "false_positives": fp,
            "false_negatives": fn,
            "true_negatives": tn,
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
            "false_positives_per_10k": round(fp / max(len(self._records), 1) * 10000, 1),
            "latency_p50_ms": round(percentile(latencies, 50), 2),
            "latency_p95_ms": round(percentile(latencies, 95), 2),
            "latency_p99_ms": round(percentile(latencies, 99), 2),
            "per_class": classes,
            "missed_detections": [
                {"scenario": r.ground_truth_scenario,
                 "threat_class": r.threat_class_expected}
                for r in self._records if r.was_missed
            ],
            "false_positive_cases": [
                {"scenario": r.ground_truth_scenario,
                 "detector_said": r.detector_threat_class}
                for r in self._records if r.was_false_positive
            ],
        }

    def reset(self) -> None:
        self._records.clear()
        self._emit_time.clear()
