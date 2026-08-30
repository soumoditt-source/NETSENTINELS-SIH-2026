# NetSentinel version comparison

This document compares the original repository behavior with the current
upgrade in this working tree. It is an engineering comparison, not a claim
that NetSentinel replaces endpoint antivirus or is universally more accurate.

## Upstream reference snapshot

The public `qwertyuiopas17/testing` README is useful as the historical baseline:
it describes four specialized model families, 89 features, ports `8000` and
`8443`, and a `99%+` F1 claim. Those claims are not treated as current evidence
because the README does not provide the split hashes, evaluation protocol, or
reproducible report behind them. This working tree keeps the repository local
and upgrades the presentation to measured values, explicit provenance, and
ports `8100` and `5174`; it does not overwrite or mutate the upstream repo.

## What changed

| Area | Earlier repository path | Current working-tree path | Why it matters |
|---|---|---|---|
| Evidence source | Demo-oriented or manually triggered evidence | Prepared CIC-IDS2017 artifact plus explicit safe metadata replay | Judges can trace every score to a source and split |
| Binary scoring | No single launch audit across all prepared splits | `tools/launch_demo.py` scores train, validation, and held-out test with 0/1 benign/non-benign metrics | Accuracy, precision, recall, F1, and ROC-AUC are printed and saved |
| Streaming validation | Scenario generation was separate from the launch path | The launch audit runs the same `FlowAnalyzer` path used by the API | Replay evidence tests the production-shaped pipeline |
| Test artifacts | No unified multi-format lab bundle | Seeded JSONL, CSV, and Parquet safe bundle with manifest and ground truth | Red/blue testing is repeatable without malware or live callbacks |
| Temporal evidence | Per-flow alerts were easier to inspect than sequence behavior | Bounded rolling windows expose IAT variation, entropy, fan-out, burst ratio, and byte asymmetry | The dashboard explains why a pattern is suspicious over time |
| Forensic upload | Upload lifecycle was less observable | Metadata jobs and offline PCAP job polling expose status, counts, and cleanup | Operators see whether evidence was accepted, processed, or rejected |
| Response handling | A threat could be read as a broad block recommendation | Alerts include a narrow containment scope and advisory action | A SOC can investigate one source, pair, or service without shutting down a network |
| Governance | Safety intent was documented but less visible during launch | Read-only, no-decryption, no-download, no-execution state is shown in the UI and report | The SIH constraint is demonstrated, not just stated |

## Measured current baseline

The repository-controlled CIC-IDS2017 binary artifact has 78 engineered flow
features and capture-grouped splits: 120,000 train rows, 60,000 validation
rows, and 60,000 test rows. The current held-out test result is F1 `0.6359`,
ROC-AUC `0.9055`, precision `0.7105`, recall `0.5754`, and accuracy `0.8476`.
The validation operating point is intentionally retained in the artifact;
these numbers are dataset-specific and do not represent universal malware
accuracy.

The safe bundle contains 449 labelled metadata events spanning benign hard
negatives, flood-like rates, reconnaissance fan-out, periodic beacon-like
timing, DGA-like DNS, DNS-tunnel-like labels, asymmetric transfer, and a
legitimate-service correlation chain. Its score is reported separately from
the real benchmark because synthetic scenario performance must not be mixed
with held-out dataset evidence.

## What remains intentionally out of scope

NetSentinel does not inspect executable contents, processes, memory, local
persistence, decrypted payloads, or live command-and-control. It does not
download malware, send probes, block traffic, or promise to outperform
Microsoft Defender. The correct comparison is complementary: endpoint tools
provide endpoint execution context, while NetSentinel provides explainable
passive network intelligence in a one-way monitoring enclave.

## Reproduce the comparison

From `testing-main`:

```powershell
python tools/launch_demo.py
python -m pytest -q
cd frontend
npm run build
```

The launch command writes `reports/launch/launch_report.json` and
`reports/launch/launch_report.md`. The dashboard reads the JSON report through
`GET /api/launch/report` and keeps live rolling telemetry separate from the
offline audit.
