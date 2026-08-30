# Data sources and governance

NetSentinel uses public datasets only through explicit user commands. The
application does not fetch a dataset or threat feed during startup.

## CIC-IDS2017

Official page: <https://www.unb.ca/cic/datasets/ids-2017.html>

CIC describes labeled flow CSVs and PCAPs covering benign traffic and several
attack families. The factory uses labeled CSVs for flow experiments. It does
not claim that CIC-IDS2017 provides labels for every SIH 26145 threat class.
Raw source and destination addresses are anonymized during preparation; source
files are never copied into model artifacts.

## Handling policy

- Review the source terms and cite the dataset paper before use.
- Record URL, retrieval time, file size, and SHA-256 in metadata.
- Never download live malware samples as part of the factory.
- Never load a downloaded pickle or joblib file.
- Keep raw data outside version control.
- Use Parquet for processed tables, JSON for provenance, and native model
  formats for trained gradient-boosting models.

Additional datasets such as CIC-DDoS2019, UNSW-NB15, CTU-13, and UGR'16 need
dataset-specific adapters and label reviews before being merged. They must not
be concatenated blindly because their capture, feature, and label semantics
differ.
