# Architecture decisions

## Local-only startup

Implicit model downloads were removed because startup must not require network
access or trust remote artifacts.

## Baselines before ML

Reconnaissance, exfiltration, and service behavior use interpretable rules and
correlation until compatible labeled data exists. A threshold is not named
XGBoost.

## Provenance-first data

Parquet stores processed tables, JSON stores manifests, and joblib is limited
to trusted local Python components. Raw identity fields are anonymized or
excluded from model inputs.
