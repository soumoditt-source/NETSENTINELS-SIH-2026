# NetSentinel SIH 2026 Presentation

**Team:** Soumdoitya Das and Team NetSentinels<br>
**Problem Statement:** 26145 - AI-Based Detection of Cyber Threats in
Unidirectional IP Traffic

This is a slide-ready story. Each slide has one message, one visual, and one
proof point so the demo remains understandable under judging time pressure.

## Slide 1 - Title

**NetSentinel**<br>
Passive cyber early warning for one-way monitoring enclaves.

**Say:** “We detect suspicious network behavior without creating a return path
into the protected network.”

**Visual:** Dark command-center dashboard with the line: *See everything.
Touch nothing. Trust the chain.*

## Slide 2 - The operational problem

- Critical infrastructure often mirrors traffic into an isolated enclave.
- Analysts can observe the traffic but cannot probe the source.
- A detector must work without a handshake, payload decryption, or blocking.

**Visual:** Production network -> one-way diode -> analytics enclave.

## Slide 3 - Our answer

NetSentinel turns passive metadata into a bounded evidence timeline:

`observe -> normalize -> aggregate -> detect -> correlate -> explain`

**Proof:** Every alert records its timestamp, flow identity, confidence,
supporting evidence, and read-only state.

## Slide 4 - What we detect

- Flood-like rate and handshake imbalance.
- Horizontal, vertical, and slow reconnaissance shape.
- Periodic beaconing and legitimate-service abuse.
- DNS entropy, DGA-like labels, and DNS tunnelling-like behavior.
- Asymmetric outbound transfer and encrypted-session metadata.

**Visual:** Coverage matrix showing active, partial, and endpoint-only families.

## Slide 5 - What makes it trustworthy

- No return traffic or automatic enforcement.
- No payload decryption and no executable handling.
- Bounded temporal windows prevent unbounded memory growth.
- Benign alternatives remain visible beside every alert.
- Model provenance and launch scores are reproducible.

## Slide 6 - The engineering

**Visual:** The Mermaid architecture in `README.md`.

**Say:** “The same analyzer path powers replay, metadata upload, live capture,
REST, and WebSocket delivery. The demo is not a separate slideware pipeline.”

## Slide 7 - Real data evidence

- CIC-IDS2017 prepared flow records.
- 78 engineered features.
- Capture-grouped train, validation, and held-out test splits.
- Held-out test ROC-AUC: 90.55%.
- Held-out test F1: 63.59%.

**Say:** “We show the score that was measured, including the lower recall. We do
not turn a dataset result into a universal malware claim.”

## Slide 8 - Live demonstration

1. Run `launch_netsentinel.bat` from the repository root.
2. Show the terminal scorecard before the windows open.
3. Open the dashboard and launch `Mixed enterprise` replay.
4. Point to the temporal window, C2 metadata FFT, alert evidence, and coverage.
5. Download the JSONL/CSV/Parquet safe fixture and show its manifest.

## Slide 9 - Why it matters to an operator

NetSentinel does not ask an analyst to shut down a company. It narrows the next
check to a source, destination pair, service, or DNS client and keeps the
decision with the authorized SOC and existing controls.

## Slide 10 - Closing

**NetSentinel is the evidence layer between passive observation and a safe
decision.**

**Final line:** “When the monitoring system has no way back, its explanation
must be strong enough to stand on its own.”
