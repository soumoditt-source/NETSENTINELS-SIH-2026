"""Run a measured local replay benchmark without inventing model results."""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Any

from netsentinel.detectors.correlation import CorrelationEngine
from netsentinel.detectors.exfiltration import ExfiltrationBaselineDetector
from netsentinel.detectors.legitimate_service_c2 import LegitimateServiceC2Detector
from netsentinel.detectors.reconnaissance import ReconnaissanceRuleDetector
from netsentinel.models.registry import ModelRegistry
from netsentinel.pipeline.alert_manager import AlertManager
from netsentinel.pipeline.analyzer import FlowAnalyzer
from netsentinel.simulator.scenario_catalog import get_scenario

from .metrics import EvaluationMetrics


def _build_analyzer(mode: str) -> FlowAnalyzer:
    registry = ModelRegistry()
    registry.recon = ReconnaissanceRuleDetector()
    registry.exfil = ExfiltrationBaselineDetector()
    registry.c2_legit = LegitimateServiceC2Detector()
    registry.correlation = CorrelationEngine()
    if mode == "pipeline":
        registry.load_all()
    return FlowAnalyzer(registry, AlertManager(max_stored=10_000))


def _events(name: str, seed: int, count: int) -> list[dict[str, Any]]:
    factory = get_scenario(name)
    if name == "mixed_enterprise":
        return list(factory(seed=seed, n_total=count))
    return list(factory(seed=seed))[:count]


def _write_csv(path: Path, rows: list[dict[str, Any]], fields: list[str]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def _summary_row(name: str, metrics: EvaluationMetrics) -> dict[str, Any]:
    result = metrics.compute()
    return {
        "scenario": name,
        "precision": result["precision"],
        "recall": result["recall"],
        "f1": result["f1"],
        "false_positives_per_10k": result["false_positives_per_10k"],
        "latency_p95_ms": result["latency_p95_ms"],
    }


def run_benchmark(
    scenario: str = "mixed_enterprise",
    events: int = 200,
    seed: int = 42,
    output_dir: str | Path = "reports/evaluation/latest",
    mode: str = "baseline",
) -> dict[str, Any]:
    """Replay a fixed event set and write only measured results."""

    if events <= 0:
        raise ValueError("events must be positive")
    analyzer = _build_analyzer(mode)
    metrics = EvaluationMetrics()
    per_scenario: dict[str, EvaluationMetrics] = {}
    replay_events = _events(scenario, seed, events)
    for event in replay_events:
        ground_truth = event.get("_ground_truth", {})
        scenario_name = str(ground_truth.get("scenario", scenario))
        scenario_metrics = per_scenario.setdefault(scenario_name, EvaluationMetrics(scenario_name))
        started = __import__("time").perf_counter()
        alert = analyzer.analyze_flow(event)
        latency = __import__("time").perf_counter() - started
        actual_attack = ground_truth.get("label") == "attack"
        predicted_attack = alert is not None
        confidence = float(alert.get("confidence", 0.0)) if alert else 0.0
        metrics.record_prediction(actual_attack, predicted_attack, confidence, latency, scenario_name)
        scenario_metrics.record_prediction(actual_attack, predicted_attack, confidence, latency)

    result = metrics.compute()
    result.update({
        "scenario": scenario,
        "seed": seed,
        "mode": mode,
        "events_requested": events,
        "events_replayed": len(replay_events),
        "tested_detectors": ["ReconnaissanceRuleDetector", "ExfiltrationBaselineDetector", "LegitimateServiceC2Detector"],
        "trained_model_metrics": "not evaluated by this baseline benchmark",
        "per_scenario": {name: value.compute() for name, value in per_scenario.items()},
    })
    destination = Path(output_dir)
    destination.mkdir(parents=True, exist_ok=True)
    (destination / "metrics.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    _write_csv(
        destination / "per_class_metrics.csv",
        [_summary_row(name, value) for name, value in per_scenario.items()],
        ["scenario", "precision", "recall", "f1", "false_positives_per_10k", "latency_p95_ms"],
    )
    _write_csv(
        destination / "confusion_matrix.csv",
        [{"actual": "attack", "predicted_attack": metrics.true_positives, "predicted_benign": metrics.false_negatives},
         {"actual": "benign", "predicted_attack": metrics.false_positives, "predicted_benign": metrics.true_negatives}],
        ["actual", "predicted_attack", "predicted_benign"],
    )
    hard_negative = per_scenario.get("cloud_sync") or per_scenario.get("normal_messaging")
    _write_csv(
        destination / "hard_negative_results.csv",
        [_summary_row(hard_negative.threat_class, hard_negative)] if hard_negative else [],
        ["scenario", "precision", "recall", "f1", "false_positives_per_10k", "latency_p95_ms"],
    )
    (destination / "executive_summary.md").write_text(
        "# NetSentinel benchmark summary\n\n"
        f"- Scenario: `{scenario}`\n- Seed: `{seed}`\n- Events replayed: `{len(replay_events)}`\n"
        f"- Mode: `{mode}`\n- Measured precision: `{result['precision']}`\n"
        f"- Measured recall: `{result['recall']}`\n- Measured F1: `{result['f1']}`\n"
        f"- Measured p95 detector latency: `{result['latency_p95_ms']} ms`\n\n"
        "These are measurements from the selected local safe replay only. They are not production claims, "
        "not cross-dataset results, and not evidence that encrypted payloads contain malware.\n",
        encoding="utf-8",
    )
    (destination / "technical_report.md").write_text(
        "# Technical benchmark report\n\n"
        "The baseline benchmark uses seeded synthetic metadata, capture-independent state, and the same "
        "FlowAnalyzer callback used by the application. It does not send packets, perform DNS lookups, "
        "decrypt payloads, or load pickle/joblib artifacts. See `metrics.json` for measured counts and "
        "`hard_negative_results.csv` for available hard-negative scenarios.\n",
        encoding="utf-8",
    )
    (destination / "false_positive_analysis.md").write_text(
        "# False-positive analysis\n\n"
        "Review every benign alert in the replay before presenting a metric. Legitimate cloud sync, "
        "scheduled updates, approved scanners, and monitoring agents can resemble suspicious behavior.\n",
        encoding="utf-8",
    )
    return result


def build_parser() -> argparse.ArgumentParser:
    """Build the benchmark CLI."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scenario", default="mixed_enterprise")
    parser.add_argument("--events", type=int, default=200)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--output-dir", default="reports/evaluation/latest")
    parser.add_argument("--mode", choices=("baseline", "pipeline"), default="baseline")
    return parser


if __name__ == "__main__":
    args = build_parser().parse_args()
    print(json.dumps(run_benchmark(args.scenario, args.events, args.seed, args.output_dir, args.mode), indent=2))
