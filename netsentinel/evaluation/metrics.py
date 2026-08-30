"""
netsentinel/evaluation/metrics.py
===================================
Honest, leakage-resistant evaluation metrics for NetSentinel detectors.

Computes:
  - Precision / Recall / F1 (macro and weighted)
  - PR-AUC (approximate, no sklearn dependency required for basic use)
  - False positives per 10,000 flows
  - Detection latency p50/p95/p99
  - Per-class breakdown
  - Calibration error (basic)

Design:
  This module is intentionally NOT tied to any specific model or dataset.
  It records raw predictions and labels, then computes all metrics on demand.
  The ground_truth.py module in the simulator uses this for replay evaluation.
"""

from __future__ import annotations

import math
from collections import defaultdict
from typing import Any


class EvaluationMetrics:
    """
    Streaming metric accumulator.

    Usage:
        m = EvaluationMetrics()
        m.record_prediction(y_true=True, y_pred=True, confidence=0.87, latency=0.012)
        m.record_prediction(y_true=True, y_pred=False, confidence=0.3, latency=0.005)
        results = m.compute()
    """

    def __init__(self, threat_class: str = "all") -> None:
        self.threat_class   = threat_class
        self.true_positives  = 0
        self.false_positives = 0
        self.false_negatives = 0
        self.true_negatives  = 0
        self.latencies: list[float]      = []
        self.confidences: list[float]    = []
        self.labels: list[int]           = []   # 1=attack, 0=benign
        self._per_class: dict[str, "EvaluationMetrics"] = {}

    # ------------------------------------------------------------------
    def record_prediction(
        self,
        y_true: bool,
        y_pred: bool,
        confidence: float = 0.0,
        latency: float = 0.0,
        threat_class: str = "",
    ) -> None:
        """Record one prediction."""
        if y_true and y_pred:
            self.true_positives  += 1
        elif not y_true and y_pred:
            self.false_positives += 1
        elif y_true and not y_pred:
            self.false_negatives += 1
        else:
            self.true_negatives  += 1

        if latency > 0:
            self.latencies.append(latency)
        self.confidences.append(confidence)
        self.labels.append(1 if y_true else 0)

        # Per-class tracking
        if threat_class:
            if threat_class not in self._per_class:
                self._per_class[threat_class] = EvaluationMetrics(threat_class)
            self._per_class[threat_class].record_prediction(
                y_true, y_pred, confidence, latency
            )

    # ------------------------------------------------------------------
    def compute(self) -> dict[str, Any]:
        """Compute and return all metrics as a JSON-serialisable dict."""
        tp = self.true_positives
        fp = self.false_positives
        fn = self.false_negatives
        tn = self.true_negatives

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall    = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1        = (2 * precision * recall / (precision + recall)
                     if (precision + recall) > 0 else 0.0)

        total     = tp + fp + fn + tn
        fp_per_10k = (fp / max(total, 1)) * 10_000

        # Latency percentiles
        lats = sorted(self.latencies)
        p50  = _percentile(lats, 50)
        p95  = _percentile(lats, 95)
        p99  = _percentile(lats, 99)
        avg_lat = sum(lats) / len(lats) if lats else 0.0

        # Basic calibration error (mean absolute calibration error)
        ace = _calibration_error(self.confidences, self.labels)

        per_class = {
            tc: m.compute()
            for tc, m in self._per_class.items()
        }
        negative_precision = tn / (tn + fn) if (tn + fn) > 0 else 0.0
        negative_recall = tn / (tn + fp) if (tn + fp) > 0 else 0.0
        negative_f1 = (
            2 * negative_precision * negative_recall / (negative_precision + negative_recall)
            if negative_precision + negative_recall > 0
            else 0.0
        )
        negative_support = tn + fp
        positive_support = tp + fn
        macro_f1 = (f1 + negative_f1) / 2
        weighted_f1 = (
            (f1 * positive_support + negative_f1 * negative_support) / max(total, 1)
        )

        return {
            "threat_class":          self.threat_class,
            "total_predictions":     total,
            "true_positives":        tp,
            "false_positives":       fp,
            "false_negatives":       fn,
            "true_negatives":        tn,
            "precision":             round(precision, 4),
            "recall":                round(recall, 4),
            "f1":                    round(f1, 4),
            "macro_f1":               round(macro_f1, 4),
            "weighted_f1":            round(weighted_f1, 4),
            "pr_auc":                 round(_pr_auc(self.confidences, self.labels), 4),
            "roc_auc":                round(_roc_auc(self.confidences, self.labels), 4),
            "false_positives_per_10k": round(fp_per_10k, 2),
            "latency_p50_ms":        round(p50 * 1000, 2),
            "latency_p95_ms":        round(p95 * 1000, 2),
            "latency_p99_ms":        round(p99 * 1000, 2),
            "latency_avg_ms":        round(avg_lat * 1000, 2),
            "calibration_error":     round(ace, 4),
            "per_class":             per_class,
            "limitations": [
                "Metrics are from synthetic replay scenarios, not production traffic.",
                "Results are scenario-dependent. Hard-negative performance may differ.",
            ],
        }

    def reset(self) -> None:
        self.true_positives = self.false_positives = 0
        self.false_negatives = self.true_negatives = 0
        self.latencies.clear()
        self.confidences.clear()
        self.labels.clear()
        self._per_class.clear()


# ── Benchmark runner ──────────────────────────────────────────────────────────

class ThroughputTracker:
    """Measures records/s, bytes/s, and queue depth."""

    def __init__(self) -> None:
        import time as _time
        self._start = _time.time()
        self.records_processed = 0
        self.bytes_processed   = 0
        self.records_dropped   = 0
        self.alerts_generated  = 0

    def record(self, bytes_: int = 0, dropped: bool = False, alerted: bool = False) -> None:
        if not dropped:
            self.records_processed += 1
            self.bytes_processed   += bytes_
        else:
            self.records_dropped   += 1
        if alerted:
            self.alerts_generated  += 1

    def report(self) -> dict[str, Any]:
        import time as _time
        elapsed = max(_time.time() - self._start, 0.001)
        return {
            "elapsed_s":        round(elapsed, 2),
            "records_processed": self.records_processed,
            "records_dropped":   self.records_dropped,
            "alerts_generated":  self.alerts_generated,
            "records_per_sec":   round(self.records_processed / elapsed, 1),
            "bytes_per_sec":     round(self.bytes_processed / elapsed, 1),
            "drop_rate_pct":     round(
                self.records_dropped / max(self.records_processed + self.records_dropped, 1) * 100, 2
            ),
        }


# ── Helpers ───────────────────────────────────────────────────────────────────

def _percentile(sorted_list: list[float], p: float) -> float:
    if not sorted_list:
        return 0.0
    idx = int(len(sorted_list) * p / 100)
    return sorted_list[min(idx, len(sorted_list) - 1)]


def _calibration_error(confidences: list[float], labels: list[int], n_bins: int = 10) -> float:
    """Mean absolute calibration error (MACE) — lower is better."""
    if not confidences:
        return 0.0
    bin_size = 1.0 / n_bins
    total_error = 0.0
    total_weight = 0
    for i in range(n_bins):
        low  = i * bin_size
        high = low + bin_size
        in_bin = [(c, l) for c, l in zip(confidences, labels) if low <= c < high]
        if not in_bin:
            continue
        avg_conf    = sum(c for c, _ in in_bin) / len(in_bin)
        avg_label   = sum(l for _, l in in_bin) / len(in_bin)
        total_error += abs(avg_conf - avg_label) * len(in_bin)
        total_weight += len(in_bin)
    return total_error / max(total_weight, 1)


def _roc_auc(scores: list[float], labels: list[int]) -> float:
    """Calculate pairwise ROC-AUC when both classes are present."""

    positives = [score for score, label in zip(scores, labels) if label == 1]
    negatives = [score for score, label in zip(scores, labels) if label == 0]
    if not positives or not negatives:
        return 0.0
    wins = sum(1.0 if positive > negative else 0.5 if positive == negative else 0.0 for positive in positives for negative in negatives)
    return wins / (len(positives) * len(negatives))


def _pr_auc(scores: list[float], labels: list[int]) -> float:
    """Calculate stepwise precision-recall area from recorded scores."""

    ranked = sorted(zip(scores, labels), key=lambda item: item[0], reverse=True)
    positives = sum(labels)
    if not positives:
        return 0.0
    true_positives = 0
    false_positives = 0
    previous_recall = 0.0
    area = 0.0
    for _, label in ranked:
        if label:
            true_positives += 1
        else:
            false_positives += 1
        recall = true_positives / positives
        precision = true_positives / (true_positives + false_positives)
        area += precision * (recall - previous_recall)
        previous_recall = recall
    return area
