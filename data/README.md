# NetSentinel data layout

Large datasets are local inputs and are not committed to this repository.
Runtime startup never downloads data. Use the explicit downloader only after
reviewing the [official CIC-IDS2017 source](https://www.unb.ca/cic/datasets/ids-2017.html).

```text
data/
  raw/cicids2017/                 user-provided CSVs or authorized archive
  processed/canonical/            canonical Parquet and optional CSV export
  processed/train/                capture-aware training table
  processed/validation/           validation table
  processed/test/                 held-out table
  artifacts/manifests/            source, hash, schema, and split manifests
  reports/quality/                cleaning counters and limitations
  reports/profiling/              schema and missing-value profiles
```

Prepare a local sample:

```bash
python tools/datasets/prepare_cicids2017.py --input-dir data/raw/cicids2017 --output-dir data --sample 10000 --export-csv
```

The factory anonymizes source/destination identities, excludes those raw
identifiers from model features, maps only explicit known labels, and records
when it must fall back from capture grouping to chronological ordering.
## NetSentinel data lanes

NetSentinel deliberately uses two complementary datasets rather than an
uncontrolled breach dump:

1. **Detection telemetry:** local CIC-IDS2017 flow CSVs, normalized into
   Parquet/CSV with stable anonymized identities, mapped labels, provenance,
   and capture-held-out train/validation/test splits. This is the supervised
   model-training lane.
2. **Investigation traces:** seeded JSONL/Parquet metadata fixtures with
   explicit ground truth and benign hard negatives. This is the streaming,
   temporal, explainability, and dashboard-replay lane.

Real breach dumps are intentionally excluded: they may contain credentials,
personal data, or uncontrolled payloads and are not required to demonstrate
the SIH passive-monitoring problem. The API accepts only bounded metadata
records and never loads uploaded pickle files.
