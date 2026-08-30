"""Train an auditable XGBoost detector from prepared local CIC-IDS2017 data.

The artifact is a binary early-warning model (benign versus non-benign). The
streaming threat-specific detectors remain responsible for DGA, beaconing,
reconnaissance, exfiltration, and metadata-only encrypted-session evidence.
This command never downloads data or trains from synthetic replay traces.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
from datetime import datetime, timezone
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

import pandas as pd
from sklearn.impute import SimpleImputer
from sklearn.metrics import classification_report, confusion_matrix, f1_score, precision_score, recall_score, roc_auc_score
from sklearn.utils.class_weight import compute_sample_weight


METADATA_COLUMNS = {
    "event_id", "flow_id", "source_identity", "destination_identity", "source_file",
    "capture_id", "dataset_source", "original_label", "canonical_label", "label_confidence",
    "is_synthetic", "observed_at", "scenario_id",
}


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _feature_columns(frame: pd.DataFrame) -> list[str]:
    return [
        column for column in frame.select_dtypes(include="number").columns
        if column not in METADATA_COLUMNS and not column.endswith("_id")
    ]


def _package_version(name: str) -> str:
    try:
        return version(name)
    except PackageNotFoundError:
        return "unavailable"


def _split_metrics(y_true: pd.Series, probabilities, threshold: float) -> dict[str, object]:
    predictions = (probabilities >= threshold).astype(int)
    return {
        "precision": float(precision_score(y_true, predictions, zero_division=0)),
        "recall": float(recall_score(y_true, predictions, zero_division=0)),
        "f1": float(f1_score(y_true, predictions, zero_division=0)),
        "macro_f1": float(f1_score(y_true, predictions, average="macro", zero_division=0)),
        "roc_auc": float(roc_auc_score(y_true, probabilities)) if y_true.nunique() == 2 else None,
        "false_positives": int(((y_true == 0) & (predictions == 1)).sum()),
        "false_negatives": int(((y_true == 1) & (predictions == 0)).sum()),
        "classification_report": classification_report(y_true, predictions, output_dict=True, zero_division=0),
    }


def _select_threshold(y_true: pd.Series, probabilities) -> tuple[float, dict[str, float]]:
    """Select an operating point on validation only, maximizing validation F1."""

    best_threshold = 0.5
    best_f1 = -1.0
    best_precision = 0.0
    best_recall = 0.0
    for step in range(1, 1000):
        threshold = step / 1000
        predictions = probabilities >= threshold
        precision = float(precision_score(y_true, predictions, zero_division=0))
        recall = float(recall_score(y_true, predictions, zero_division=0))
        score = float(f1_score(y_true, predictions, zero_division=0))
        if (score, precision, recall) > (best_f1, best_precision, best_recall):
            best_threshold = threshold
            best_f1 = score
            best_precision = precision
            best_recall = recall
    return best_threshold, {"f1": best_f1, "precision": best_precision, "recall": best_recall}


def train_artifact(data_dir: str | Path, output_dir: str | Path, seed: int = 42) -> dict[str, object]:
    """Fit and evaluate XGBoost on prepared, capture-aware split tables."""

    try:
        from xgboost import XGBClassifier
    except ImportError as exc:
        raise RuntimeError("xgboost is required for this opt-in training command") from exc

    root = Path(data_dir).resolve()
    split_paths = {
        name: root / "processed" / name / f"cicids2017_{name}.parquet"
        for name in ("train", "validation", "test")
    }
    missing = [str(path) for path in split_paths.values() if not path.is_file()]
    if missing:
        raise FileNotFoundError("Prepared split tables are missing: " + ", ".join(missing))
    frames = {name: pd.read_parquet(path) for name, path in split_paths.items()}
    features = _feature_columns(frames["train"])
    if not features:
        raise ValueError("No numeric training features remain after leakage exclusions")

    x_train = frames["train"].reindex(columns=features, fill_value=0)
    x_validation = frames["validation"].reindex(columns=features, fill_value=0)
    x_test = frames["test"].reindex(columns=features, fill_value=0)
    y_train = (frames["train"]["canonical_label"] != "benign").astype(int)
    y_validation = (frames["validation"]["canonical_label"] != "benign").astype(int)
    y_test = (frames["test"]["canonical_label"] != "benign").astype(int)
    if y_train.nunique() < 2 or y_test.nunique() < 2:
        raise ValueError("Train and test splits must each contain benign and non-benign rows")

    preprocessing = SimpleImputer(strategy="median")
    x_train_transformed = preprocessing.fit_transform(x_train)
    x_validation_transformed = preprocessing.transform(x_validation)
    x_test_transformed = preprocessing.transform(x_test)
    model = XGBClassifier(
        n_estimators=140,
        max_depth=6,
        learning_rate=0.08,
        subsample=0.85,
        colsample_bytree=0.85,
        objective="binary:logistic",
        eval_metric="logloss",
        tree_method="hist",
        n_jobs=2,
        random_state=seed,
    )
    model.fit(
        x_train_transformed,
        y_train,
        sample_weight=compute_sample_weight(class_weight="balanced", y=y_train),
        eval_set=[(x_validation_transformed, y_validation)],
        verbose=False,
    )
    validation_probabilities = model.predict_proba(x_validation_transformed)[:, 1]
    test_probabilities = model.predict_proba(x_test_transformed)[:, 1]
    threshold, threshold_selection = _select_threshold(y_validation, validation_probabilities)
    metrics = {
        "model_scope": "binary_benign_vs_non_benign",
        "threshold_selection": {
            "method": "validation_f1_maximization",
            "threshold": threshold,
            "validation_operating_point": threshold_selection,
        },
        "validation": _split_metrics(y_validation, validation_probabilities, threshold),
        "test": _split_metrics(y_test, test_probabilities, threshold),
    }

    artifact_dir = Path(output_dir).resolve() / "cicids2017_attack_xgboost" / "v1"
    artifact_dir.mkdir(parents=True, exist_ok=True)
    import joblib

    joblib.dump(preprocessing, artifact_dir / "preprocessing_pipeline.joblib")
    joblib.dump(model, artifact_dir / "model.joblib")
    model.save_model(artifact_dir / "model.json")
    (artifact_dir / "feature_order.json").write_text(json.dumps(features, indent=2) + "\n", encoding="utf-8")
    (artifact_dir / "feature_schema.json").write_text(json.dumps({feature: str(x_train[feature].dtype) for feature in features}, indent=2) + "\n", encoding="utf-8")
    (artifact_dir / "label_mapping.json").write_text(json.dumps({"0": "benign", "1": "non_benign"}, indent=2) + "\n", encoding="utf-8")
    (artifact_dir / "metrics.json").write_text(json.dumps(metrics, indent=2) + "\n", encoding="utf-8")
    predictions = (test_probabilities >= threshold).astype(int)
    pd.DataFrame(confusion_matrix(y_test, predictions), index=["benign", "non_benign"], columns=["benign", "non_benign"]).to_csv(artifact_dir / "confusion_matrix.csv")
    pd.DataFrame({"feature": features, "importance": model.feature_importances_}).sort_values("importance", ascending=False).to_csv(artifact_dir / "feature_importance.csv", index=False)
    label_distribution = {
        name: frames[name]["canonical_label"].value_counts(dropna=False).to_dict()
        for name in frames
    }
    manifest = {
        "model_name": "cicids2017_attack_xgboost",
        "model_version": "v1",
        "detector_name": "cicids2017_non_benign_xgboost",
        "model_type": "supervised_binary_classifier",
        "training_run_id": datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ"),
        "creation_timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "algorithm": "XGBClassifier histogram gradient boosting with balanced sample weights",
        "random_seed": seed,
        "feature_schema_version": "1.0.0",
        "features": features,
        "row_counts": {name: int(len(frame)) for name, frame in frames.items()},
        "label_distribution": label_distribution,
        "source_split_sha256": {name: _sha256(path) for name, path in split_paths.items()},
        "split_method": "prepared CIC-IDS2017 capture-grouped or documented chronological fallback",
        "threshold": threshold,
        "calibration": "not fitted; operating threshold selected on validation F1",
        "python_version": platform.python_version(),
        "package_versions": {name: _package_version(name) for name in ("pandas", "scikit-learn", "xgboost", "joblib")},
        "limitations": [
            "This is a binary early-warning detector for prepared CIC-IDS2017 labels, not a universal threat classifier.",
            "CIC-IDS2017 Bot labels are a proxy for botnet/C2-like traffic; they do not prove C2 intent.",
            "It does not decrypt payloads, issue network actions, or replace streaming threat-specific detectors.",
            "Metrics are dataset-specific and must not be presented as production performance.",
        ],
    }
    (artifact_dir / "training_manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    (artifact_dir / "model_metadata.json").write_text(json.dumps(manifest | {"metrics": metrics}, indent=2) + "\n", encoding="utf-8")
    (artifact_dir / "known_limitations.md").write_text(
        "# Known limitations\n\n"
        "This artifact is a supervised local XGBoost model trained only from prepared CIC-IDS2017 splits. "
        "It is a binary early-warning signal; the streaming rule and correlation layers provide the "
        "threat-specific explanations. Verify the checksums before serving it.\n",
        encoding="utf-8",
    )
    checksums = {str(path.name): _sha256(path) for path in artifact_dir.iterdir() if path.is_file() and path.name != "sha256sums.json"}
    (artifact_dir / "sha256sums.json").write_text(json.dumps(checksums, indent=2) + "\n", encoding="utf-8")
    return {"artifact_dir": str(artifact_dir), "metrics": metrics, "features": features}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", default="data")
    parser.add_argument("--output-dir", default="data/artifacts/models")
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()
    print(json.dumps(train_artifact(args.data_dir, args.output_dir, args.seed), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
