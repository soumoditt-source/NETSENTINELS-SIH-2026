# Safe lab

`netsentinel/simulator` emits synthetic metadata only. The lab uses private
internal ranges and documentation-only external ranges, fixed seeds, explicit
ground truth, jitter, and benign hard negatives. It does not run scanners,
flooders, C2 clients, DNS tunnels, uploaders, malware, or external service
connections.

Generate a bundle with:

```bash
python tools/datasets/build_safe_scenarios.py --scenario mixed_enterprise --events 200 --seed 42
```

The output includes JSONL, CSV, Parquet, and a manifest with checksums.

## Downloadable detector test bundle

Build the deterministic multi-scenario bundle used by the dashboard download
buttons:

```bash
python tools/safe_lab/build_attack_test_bundle.py --seed 42
```

It writes `data/processed/safe_lab/netsentinel_attack_test_bundle_42/` with
JSONL, CSV, Parquet, a SHA-256 manifest, and a short README. The bundle covers
benign hard negatives plus SYN/UDP flood-like rates, horizontal and vertical
port-scan fan-out, low-and-slow scanning, periodic beacon-like timing, DGA-like
DNS, DNS-tunnelling-like metadata, asymmetric transfer, and a legitimate-cloud
service correlation chain. Every record is synthetic metadata on documentation
networks; it is not an exploit, malware sample, packet capture, payload, or
executable file.

The running API exposes the generated files at:

```text
GET http://localhost:8100/api/forensics/fixtures
GET http://localhost:8100/api/forensics/fixtures/jsonl
GET http://localhost:8100/api/forensics/fixtures/csv
GET http://localhost:8100/api/forensics/fixtures/parquet
```

For a focused legitimate-service hard negative:

```bash
python tools/safe_lab/build_hard_negative_fixture.py --seed 42
```

It is safe to upload as metadata to the replay harness; it is deliberately
not an executable attack sample and cannot validate endpoint-malware evasion.

## Dashboard evidence drop

The Explain view accepts only `.jsonl`, `.ndjson`, `.csv`, and `.parquet` flow
metadata through `POST /api/forensics/upload`. Each job is limited to 25 MB and
20,000 records, rejects payload-bearing fields, reports a job ID, broadcasts
alerts over the existing WebSocket, and deletes the temporary upload after
processing. `.pkl` is never accepted: pickle can execute code during loading.

The same adapter is available offline for CSV, JSONL, and Parquet replay via
`netsentinel.ingest.flow_adapter.iter_analyzer_events`. It normalizes records
to the streaming analyzer contract and preserves no packet content.
