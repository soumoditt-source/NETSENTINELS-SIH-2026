# CIC-IDS2017 factory

The factory has three deliberately separate stages:

1. `download_cic.py download` optionally retrieves one authorized archive and
   writes a SHA-256 provenance record.
2. `prepare_cicids2017.py` discovers CSVs, normalizes known column variants,
   cleans numeric values, maps explicit labels, anonymizes identities, and
   writes canonical Parquet.
3. `build_training_artifacts.py` trains a local logistic baseline only when
   all three prepared split tables contain usable labels.

Capture groups are held out where at least three captures exist. With one
capture, the factory uses chronological ordering when timestamps are valid and
records the fallback in the split manifest. This is not equivalent to a
capture holdout.

Never put raw data, raw IP addresses, or a complete dataframe into a pickle or
joblib file. See `netsentinel/models/artifact_security.py` before loading any
Python artifact.
