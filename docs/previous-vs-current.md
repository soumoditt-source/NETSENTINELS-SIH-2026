# Previous GitHub Baseline vs Current NetSentinel

**Repository:** `NETSENTINELS-SIH-2026`<br>
**Team:** Soumdoitya Das and Team NetSentinels

This comparison separates the earlier project baseline from the current
SIH-ready branch. It does not claim that a network sensor replaces Defender,
EDR, Zeek, Suricata, or a full SOC platform.

## Executive difference

The earlier baseline presented several model families and a dashboard. The
current branch turns that concept into one traceable product path: real data
artifact -> bounded streaming analyzer -> versioned alert -> live dashboard ->
reproducible launch report.

## Capability comparison

| Area | Earlier baseline | Current branch | Why the current design is stronger |
|---|---|---|---|
| Primary contract | Broad threat-model demonstration | Explicit passive, read-only metadata contract | Fits the one-way enclave constraint directly |
| Data provenance | Model files and demo paths were easier to inspect separately | Prepared CIC-IDS2017 splits, hashes, manifest, and trusted artifact | A judge can trace the score to a controlled input |
| Model evidence | Headline model claims were not unified in one launch path | Train, validation, and held-out test metrics print before startup | Weak generalization is visible instead of hidden |
| Streaming path | Simulation and UI were separate concerns | Replay, WebSocket, temporal state, and dashboard share the analyzer path | The demo exercises production-shaped behavior |
| Alert explanation | Detection focus | Evidence, limitations, benign alternatives, MITRE mapping, scoped next step | Helps a human decide what to verify |
| C2 analysis | C2 model concept and FFT presentation | Backend supporting evidence is normalized into live C2 indicators and interval view | Temporal visualizations reflect observed alert data |
| Temporal analysis | Flow-level presentation | Bounded rolling window with IAT CV, entropy, fan-out, burst, and byte asymmetry | Repeated behavior is not reduced to one flow |
| Test data | Separate demo fixtures | Seeded 449-event JSONL/CSV/Parquet safe bundle with manifest | Red/blue rehearsal is repeatable and safe |
| UI state | Preview behavior could be mistaken for live telemetry | Offline, live, and explicitly enabled preview states are distinct | The screen does not invent a live feed silently |
| Upload boundary | General project intent | Metadata and authorized PCAP only; executables, payloads, and pickle rejected | Safer for a monitoring enclave and a public repository |
| Launch experience | Manual startup steps | One batch launcher scores first, then reuses or starts services | A judge sees proof before the dashboard opens |
| Operations | Detection showcase | Health, coverage, launch report, replay controls, and stop command | Easier to run, inspect, and hand over |

## Measured current evidence

- CIC-IDS2017 test accuracy: `84.76%`.
- CIC-IDS2017 test precision: `71.05%`.
- CIC-IDS2017 test recall: `57.54%`.
- CIC-IDS2017 test F1: `63.59%`.
- CIC-IDS2017 test ROC-AUC: `90.55%`.
- Safe 449-event replay F1: `71.09%`; safe replay precision: `100%`.

These values are not forced to 90% or 100%. A reliable submission shows where
the model works, where it misses, and what additional endpoint or asset context
would improve the decision.

## Why it is better for SIH

1. **It matches the problem constraints.** No probe, callback, return path,
   payload decryption, or inline blocking is required.
2. **It is demonstrable.** A clean launcher produces terminal evidence before
   the UI opens, and the same evidence is visible in the dashboard.
3. **It is explainable.** Analysts see the behavior, timing, confidence,
   alternative explanations, and next verification step together.
4. **It is testable.** Safe scenarios cover both attack-like patterns and
   hard-negative legitimate traffic in three file formats.
5. **It is honest about scope.** Endpoint-only malware behavior remains a
   documented boundary rather than an unsupported promise.

## What should be added next in a production deployment

- Organization-specific baselines and approved-service context.
- Longer retention and fleet identity for distributed reconnaissance.
- Endpoint/identity correlation for process and account attribution.
- PCAP/Zeek performance testing on the target sensor hardware.
- Calibrated thresholds using representative authorized traffic.

The current branch is therefore a strong, runnable SIH prototype and evidence
platform—not a claim of universal malware detection or automatic response.
