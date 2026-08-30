# Model artifacts

The repository contains legacy ONNX files but does not claim they were trained
by the current factory. New local artifacts belong under
`data/artifacts/models/<name>/<version>/` and must include feature order,
schema, labels, split/source hashes, metrics, limitations, and checksums.

The opt-in training command currently produces a logistic supervised baseline
for binary CIC-IDS2017 benign/non-benign classification. It does not call that
artifact XGBoost. XGBoost native JSON/UBJ is preferred if a future training run
adds that dependency. Joblib is reserved for trusted local preprocessing and
calibration objects and must be checksum-verified before loading.
