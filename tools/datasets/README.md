# Dataset commands

- `download_cic.py download`: explicit authorized archive retrieval.
- `verify_dataset.py`: local file sizes and SHA-256 manifest.
- `profile_dataset.py`: bounded CSV schema/null profile.
- `prepare_cicids2017.py`: canonical Parquet, CSV export, quality report, and
  leakage-aware splits.
- `build_training_artifacts.py`: optional local supervised XGBoost artifact.
- `build_safe_scenarios.py`: offline synthetic metadata bundles.

Compatibility entry points `normalize_to_canonical.py` and `build_splits.py`
delegate to the CIC factory. They do not bypass its provenance or split policy.
