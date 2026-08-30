"""Repository-controlled CIC-IDS2017 XGBoost inference adapter."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pandas as pd

from netsentinel.config import PROJECT_ROOT
from netsentinel.models.artifact_security import load_trusted_joblib, validate_trusted_artifact


class CICIDSXGBoostDetector:
    """Use the trained binary artifact as a bounded, metadata-only signal."""

    def __init__(self, artifact_dir: str | Path | None = None):
        self.artifact_dir = Path(artifact_dir or PROJECT_ROOT / "data/artifacts/models/cicids2017_attack_xgboost/v1").resolve()
        checksums_path = self.artifact_dir / "sha256sums.json"
        if not checksums_path.is_file():
            raise FileNotFoundError(f"Trusted checksum manifest not found: {checksums_path}")
        checksums = json.loads(checksums_path.read_text(encoding="utf-8"))
        self.preprocessing = load_trusted_joblib(
            self.artifact_dir / "preprocessing_pipeline.joblib",
            self.artifact_dir,
            checksums["preprocessing_pipeline.joblib"],
        )
        from xgboost import XGBClassifier

        model_path = self.artifact_dir / "model.json"
        validate_trusted_artifact(model_path, self.artifact_dir, checksums["model.json"])
        self.model = XGBClassifier()
        self.model.load_model(model_path)
        self.feature_order = json.loads((self.artifact_dir / "feature_order.json").read_text(encoding="utf-8"))
        metadata = json.loads((self.artifact_dir / "training_manifest.json").read_text(encoding="utf-8"))
        self.threshold = float(metadata.get("threshold", 0.5))
        self.model_version = str(metadata.get("model_version", "unknown"))
        self.training_manifest = metadata

    @staticmethod
    def _normalize_key(value: str) -> str:
        return re.sub(r"\s+", " ", str(value).strip().lower())

    def predict(self, features: dict) -> dict:
        normalized = {self._normalize_key(key): value for key, value in features.items()}
        values = []
        available = 0
        for feature in self.feature_order:
            value = normalized.get(self._normalize_key(feature))
            if value is None:
                values.append(float("nan"))
                continue
            try:
                values.append(float(value))
                available += 1
            except (TypeError, ValueError):
                values.append(float("nan"))
        coverage = available / max(len(self.feature_order), 1)
        frame = pd.DataFrame([values], columns=self.feature_order)
        transformed = self.preprocessing.transform(frame)
        probability = float(self.model.predict_proba(transformed)[0, 1])
        is_attack = probability >= self.threshold
        return {
            "threat": "CIC behavioral anomaly" if is_attack else "Benign",
            "confidence": probability if is_attack else 1.0 - probability,
            "is_attack": is_attack,
            "subtype": "non_benign_flow" if is_attack else "benign_flow",
            "model": "CIC-IDS2017 XGBoost",
            "model_version": self.model_version,
            "model_status": "trained_real_data_capture_held_out",
            "method": "CIC-IDS2017 flow features; capture-held-out threshold",
            "evidence": [
                f"Non-benign flow probability {probability:.3f}",
                f"Feature coverage {available}/{len(self.feature_order)}",
                f"Operating threshold {self.threshold:.3f} selected on validation only",
            ],
            "feature_snapshot": {
                "feature_coverage": round(coverage, 3),
                "probability": round(probability, 4),
                "threshold": self.threshold,
            },
            "limitations": self.training_manifest.get("limitations", []),
        }
