# Ethical Red/Blue Testing Guide

## Boundary

The red team in this repository is a **behavior emulator**: it produces
synthetic network metadata resembling attack signatures without sending packets
or running malware. Do not add live malware, exploit code, C2 clients,
obfuscated scripts, credential material, or files designed to evade Defender.
The blue team is the detector, temporal evidence store, dashboard, and human
verification workflow.

## Safe red-team cases

Run the deterministic bundle:

```powershell
python tools/safe_lab/build_attack_test_bundle.py --seed 42
```

Generated files are in
`data/processed/safe_lab/netsentinel_attack_test_bundle_42/`:

- `attack_signatures_42.jsonl` — replay-friendly source records
- `attack_signatures_42.csv` — analyst-readable tabular view
- `attack_signatures_42.parquet` — efficient columnar view
- `attack_signatures_42.manifest.json` — counts, safety flags, and SHA-256 hashes

The bundle includes benign hard negatives and metadata patterns for SYN/UDP
floods, horizontal/vertical/low-and-slow reconnaissance, periodic beacons,
DGA-like DNS, DNS-tunnel-like labels, asymmetric transfer, and suspicious use
of a legitimate cloud service. Documentation-only IP ranges are used.

## Run the blue-team exercise

1. Start the backend with `python run.py`.
2. Start the dashboard with `npm run dev -- --host 0.0.0.0 --port 5174` from `frontend`.
3. Open `http://localhost:5174`.
4. Select a safe scenario and click **Launch analysis**.
5. In Explain mode, upload one generated file and inspect the alert evidence,
   temporal features, confidence, limitations, and scoped response guidance.
6. Use **Stop** and **Reset** between cases to keep runs comparable.

Equivalent API checks:

```powershell
curl.exe http://localhost:8100/api/replay/scenarios
curl.exe -X POST "http://localhost:8100/api/replay/start?scenario=port_scan"
curl.exe -X POST http://localhost:8100/api/replay/stop
curl.exe -X POST http://localhost:8100/api/forensics/upload -F "file=@attack_signatures_42.jsonl"
# For an authorized PCAP upload, poll the returned job_id:
curl.exe http://localhost:8100/api/pcap/jobs/{job_id}
```

## What a good test proves

| Question | Evidence |
|---|---|
| Did ingest remain passive? | Health and alert records show `read_only=true`. |
| Was content inspected? | `payload_decrypted=false`; forbidden keys are rejected. |
| Is it streaming? | WebSocket alerts arrive during replay; temporal state updates incrementally. |
| Is the alert explainable? | Evidence, feature snapshot, model version, limitations, and MITRE mapping are present. |
| Is the response narrow? | `containment_scope` identifies a source/flow/service boundary and never blocks automatically. |
| Is performance reproducible? | Bundle seed, manifest, record count, and measured events/sec are recorded. |

## Endpoint antivirus validation

NetSentinel does not replace endpoint antivirus. If an endpoint-control smoke
test is needed, use a harmless industry-standard antivirus test artifact such
as EICAR only in an isolated authorized VM, following the vendor's procedure.
Do not upload that file to NetSentinel and do not substitute a live malware
sample. NetSentinel's relevant comparison is the network behavior observed
around the endpoint, not whether it can classify a file on disk.

## Educational datasets

CIC-IDS2017 is the repository's current real flow benchmark. CTU-13 is useful
for botnet-flow research, and CIC-DDoS2019 / UNSW-NB15 can extend coverage after
schema and label review. Keep raw captures outside version control, verify
terms, hash every source, and do not concatenate datasets with incompatible
feature semantics. The factory is opt-in and never downloads data at startup.
