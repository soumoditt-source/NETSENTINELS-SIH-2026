"""Run the local evidence audit and safe replay score before server launch.

This command never downloads data, executes uploaded files, or retrains by
accident. It scores every locally prepared CIC-IDS2017 split with the trusted
repository artifact, runs the full streaming pipeline on the safe mixed suite,
and writes one report consumed by the dashboard.
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def _metric_row(labels, probabilities, threshold: float) -> dict[str, Any]:
    from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score, roc_auc_score

    predictions = probabilities >= threshold
    return {
        "rows": int(len(labels)),
        "positive_rate": round(float(labels.mean()), 4),
        "accuracy": round(float(accuracy_score(labels, predictions)), 4),
        "precision": round(float(precision_score(labels, predictions, zero_division=0)), 4),
        "recall": round(float(recall_score(labels, predictions, zero_division=0)), 4),
        "f1": round(float(f1_score(labels, predictions, zero_division=0)), 4),
        "macro_f1": round(float(f1_score(labels, predictions, average="macro", zero_division=0)), 4),
        "roc_auc": round(float(roc_auc_score(labels, probabilities)), 4) if len(set(labels)) == 2 else None,
    }


def score_prepared_real_data() -> dict[str, Any]:
    """Score all available prepared splits without changing the artifact."""
    import numpy as np
    import pandas as pd
    import pyarrow.parquet as parquet

    from netsentinel.models.cicids_xgboost import CICIDSXGBoostDetector

    artifact_dir = ROOT / "data/artifacts/models/cicids2017_attack_xgboost/v1"
    split_paths = {
        name: ROOT / "data/processed" / name / f"cicids2017_{name}.parquet"
        for name in ("train", "validation", "test")
    }
    missing = [str(path) for path in split_paths.values() if not path.is_file()]
    if missing or not (artifact_dir / "model.json").is_file():
        return {"status": "not_available", "missing": missing or [str(artifact_dir / "model.json")]}

    detector = CICIDSXGBoostDetector(artifact_dir)
    split_metrics: dict[str, Any] = {}
    started = time.perf_counter()
    for name, path in split_paths.items():
        available_columns = set(parquet.ParquetFile(path).schema.names)
        if "canonical_label" not in available_columns:
            return {"status": "not_available", "missing": [f"{path}: canonical_label"]}
        requested_columns = [
            column for column in ["canonical_label", *detector.feature_order]
            if column in available_columns
        ]
        labels_parts = []
        probability_parts = []
        parquet_file = parquet.ParquetFile(path)
        for batch in parquet_file.iter_batches(columns=requested_columns, batch_size=20_000):
            frame = batch.to_pandas()
            x_frame = frame.reindex(columns=detector.feature_order, fill_value=0).astype("float32")
            transformed = detector.preprocessing.transform(x_frame)
            probability_parts.append(detector.model.predict_proba(transformed)[:, 1])
            labels_parts.append((frame["canonical_label"] != "benign").astype(int).to_numpy())
        probabilities = np.concatenate(probability_parts)
        labels = np.concatenate(labels_parts)
        split_metrics[name] = _metric_row(labels, probabilities, detector.threshold)
    return {
        "status": "measured_real_data",
        "dataset": "CIC-IDS2017",
        "artifact": str(artifact_dir.relative_to(ROOT)),
        "features": len(detector.feature_order),
        "threshold": detector.threshold,
        "elapsed_ms": round((time.perf_counter() - started) * 1000, 2),
        "splits": split_metrics,
        "note": "Train is a fit diagnostic; validation and test are the generalization evidence.",
    }


def run_safe_pipeline_score() -> dict[str, Any]:
    """Score the complete repository-local safe bundle through FlowAnalyzer."""
    from netsentinel.evaluation.metrics import EvaluationMetrics
    from netsentinel.evaluation.run_benchmark import _build_analyzer

    fixture_candidates = [
        ROOT / "data" / "processed" / "safe_lab" / "netsentinel_attack_test_bundle_42",
        ROOT / "test_data" / "netsentinel_attack_test_bundle_42",
    ]
    fixture_dir = next(
        (candidate for candidate in fixture_candidates if (candidate / "attack_signatures_42.jsonl").is_file()),
        fixture_candidates[-1],
    )
    fixture_path = fixture_dir / "attack_signatures_42.jsonl"
    if not fixture_path.is_file():
        return {
            "status": "not_available",
            "events_replayed": 0,
            "message": "Generate the safe bundle with tools/safe_lab/build_attack_test_bundle.py first.",
        }
    analyzer = _build_analyzer("pipeline")
    metrics = EvaluationMetrics("safe_attack_signatures")
    started = time.perf_counter()
    event_count = 0
    with fixture_path.open(encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            event = json.loads(line)
            event_count += 1
            truth = event.get("_ground_truth", {})
            actual_attack = truth.get("label") == "attack"
            event_started = time.perf_counter()
            alert = analyzer.analyze_flow(event)
            metrics.record_prediction(
                actual_attack,
                alert is not None,
                float(alert.get("confidence", 0.0)) if alert else 0.0,
                time.perf_counter() - event_started,
                str(truth.get("scenario", "unknown")),
            )
    result = metrics.compute()
    result.update({
        "scenario": "attack_signatures",
        "seed": 42,
        "mode": "pipeline",
        "events_requested": event_count,
        "events_replayed": event_count,
        "accuracy": round((metrics.true_positives + metrics.true_negatives) / max(event_count, 1), 4),
        "elapsed_ms": round((time.perf_counter() - started) * 1000, 2),
        "fixture": str(fixture_path.relative_to(ROOT)),
        "binary_target": "0=benign, 1=attack",
        "format_audit": _audit_safe_fixture_formats(fixture_dir),
    })
    output_dir = ROOT / "reports" / "evaluation" / "launch"
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "safe_attack_signatures_metrics.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result


def _audit_safe_fixture_formats(fixture_dir: Path) -> dict[str, Any]:
    """Verify the three downloadable representations without rescoring them."""
    import hashlib

    formats: dict[str, Any] = {}
    for suffix in ("jsonl", "csv", "parquet"):
        path = fixture_dir / f"attack_signatures_42.{suffix}"
        digest = hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None
        formats[suffix] = {"exists": path.is_file(), "sha256": digest, "size_bytes": path.stat().st_size if path.is_file() else 0}
    return formats


def main() -> int:
    print("=" * 72)
    print(" NetSentinel launch audit | SIH 26145 | read-only metadata pipeline")
    print("=" * 72)
    print("[1/3] Scoring locally prepared CIC-IDS2017 splits...")
    real_data = score_prepared_real_data()
    if real_data["status"] == "measured_real_data":
        for split, metrics in real_data["splits"].items():
            print(
                f"  {split:10} rows={metrics['rows']:,} accuracy={metrics['accuracy']:.4f} "
                f"precision={metrics['precision']:.4f} recall={metrics['recall']:.4f} "
                f"F1={metrics['f1']:.4f} ROC-AUC={metrics['roc_auc']}")
    else:
        print(f"  [INFO] Real split scoring unavailable: {', '.join(real_data['missing'])}")

    print("[2/3] Running full streaming pipeline on safe mixed telemetry...")
    safe_score = run_safe_pipeline_score()
    if safe_score.get("status") == "not_available":
        print(f"  [INFO] Safe replay unavailable: {safe_score['message']}")
    else:
        print(
            f"  events={safe_score['events_replayed']} accuracy={safe_score['accuracy']:.4f} "
            f"precision={safe_score['precision']:.4f} recall={safe_score['recall']:.4f} "
            f"F1={safe_score['f1']:.4f} p95_latency_ms={safe_score['latency_p95_ms']:.3f}")

    report = {
        "generated_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "ports": {"backend": 8100, "frontend": 5174},
        "real_data": real_data,
        "safe_pipeline": safe_score,
        "safety": {
            "read_only": True,
            "payload_decrypted": False,
            "downloads_at_startup": False,
            "malware_or_executable_testing": False,
        },
        "interpretation": "Scores are dataset/scenario-specific and are not a universal malware detection rate.",
    }
    report_dir = ROOT / "reports/launch"
    report_dir.mkdir(parents=True, exist_ok=True)
    report_path = report_dir / "launch_report.json"
    report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    (report_dir / "launch_report.md").write_text(
        "# NetSentinel launch report\n\n"
        f"Generated: `{report['generated_at_utc']}`\n\n"
        "This report is produced before the local servers start. It scores all "
        "prepared real-data splits and runs the safe streaming pipeline. It does "
        "not download or execute malware, send packets, decrypt payloads, or "
        "claim universal accuracy. See `launch_report.json` for full values.\n",
        encoding="utf-8",
    )
    print(f"[3/3] Report written: {report_path.relative_to(ROOT)}")
    print("      Backend:  http://localhost:8100")
    print("      Dashboard: http://localhost:5174")
    print("      API docs:  http://localhost:8100/docs")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
