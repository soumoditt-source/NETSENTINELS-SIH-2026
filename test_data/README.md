# NetSentinel test data

This folder is reserved for repository-local, safe detector test evidence.
Generate the current multi-case files with:

```powershell
python tools/safe_lab/build_attack_test_bundle.py --seed 42 --output-dir test_data
```

The generated folder contains JSONL, CSV, and Parquet **network metadata
signatures** for benign hard negatives, SYN/UDP flood-like rates,
horizontal/vertical/low-and-slow reconnaissance, periodic beacon-like timing,
DGA-like DNS, DNS-tunnel-like labels, asymmetric transfers, and a
legitimate-service correlation chain.

These are not malware, executables, exploit files, payloads, credentials, or
live traffic. Use them with the dashboard's Explain-mode evidence drop to test
the real NetSentinel analysis path safely.
