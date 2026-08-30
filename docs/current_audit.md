# Current audit

Audit scope: repository and live stack inspected on 2026-08-30.

## Implemented

- FastAPI, WebSocket, Scapy/Zeek adapters, bounded temporal state, XGBoost,
  seven rule/correlation detectors, structured alerts, and React dashboard.
- Real CIC-IDS2017 flow preparation and repository-controlled XGBoost artifact:
  240,000 sampled rows, 78 features, capture-grouped splits, and manifest
  hashes.
- Safe red/blue replay controls: selectable live scenarios, Launch/Stop/Reset,
  JSONL/CSV/Parquet upload, downloadable deterministic fixtures, and scoped
  response guidance.
- Strict read-only behavior: no probes, no network callbacks, no payload
  decryption, no automatic blocking, and no runtime dataset/model downloads.
- Upload validation rejects payload-like fields, credentials, executables, and
  pickle files; files are bounded and deleted after processing.
- Threat coverage contract: `21` major network-behavior families mapped as
  `7` active, `11` partial, and `3` endpoint-only; served at `/api/coverage`
  and rendered in the single-page dashboard.

## Measured validation

- Real CIC-IDS2017 test F1: `0.6359`; test ROC-AUC: `0.9055`.
- Prepared split: train `120,000`, validation `60,000`, test `60,000`.
- Safe bundle: `449` metadata events across benign hard negatives and attack
  signatures; JSONL, CSV, and Parquet replay completed successfully.
- Launch audit: complete `449`-event safe bundle and all prepared real-data
  splits scored through `tools/launch_demo.py`; report saved under
  `reports/launch/launch_report.json`.
- Focused Python suite: `45 passed`, `4 skipped` because optional ONNX runtime
  artifacts are not installed in this environment.
- PCAP-specific tests remain dependency-gated until Scapy/Npcap is installed;
  safe JSONL, CSV, and Parquet paths are fully exercised.
- Frontend production build: passed; the remaining large-chunk warning is from
  the 3D dependency and does not block the build.
- Live services: backend `http://localhost:8100`, dashboard `http://localhost:5174`.

## Deliberate limitations

- NetSentinel is not an endpoint antivirus and cannot classify a file, process
  tree, memory injection, or local persistence from one-way flow metadata.
- Metadata can indicate suspicious behavior but cannot prove malware or intent.
- Authorized scanners, backups, updates, cloud sync, and automation can look
  suspicious; human and endpoint corroboration are required.
- Optional legacy ONNX wrappers remain unavailable unless their runtime and
  verified artifacts are installed; the active real-data artifact is XGBoost.
- Live packet capture requires an authorized host, Scapy/Npcap, and interface
  permissions. It is not enabled by safe replay tests.

## Security position

Do not weaken the safety boundary to obtain a Defender-evasion sample. The
defensible product is a passive NDR/forensics layer that complements endpoint
controls. Use the safe bundle or sanitized authorized telemetry for demos, and
keep live malware and sensitive captures outside this repository.
