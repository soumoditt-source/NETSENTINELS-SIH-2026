# NetSentinel Technical Defense Blueprint

## Purpose

NetSentinel is a passive network detection and response intelligence layer for
unidirectional monitoring enclaves. It consumes flow, DNS, TLS, QUIC, Zeek, or
PCAP-derived metadata and produces bounded-latency, explainable alerts. It is
not an antivirus engine and it never executes, opens, decrypts, blocks, or
returns traffic.

## Runtime path

```text
tap / data diode / PCAP / Zeek JSON
        -> metadata normalizer
        -> bounded 300 s temporal state
        -> XGBoost + stateful detectors
        -> correlation and evidence schema
        -> WebSocket + REST + dashboard
```

The canonical event has an event ID, flow ID, timestamp, source and destination
identities, ports, protocol, byte/packet counters, direction, and optional DNS
or TLS/QUIC metadata. Payload fields are rejected at the upload boundary.

## Detection layers

| Layer | What it contributes | Current status |
|---|---|---|
| CIC-IDS2017 XGBoost | 78 engineered flow features and binary benign/non-benign score | Trained on local real flow data |
| Volumetric baseline | SYN/ACK imbalance, packet rate, byte rate, protocol context | Live rule detector |
| Reconnaissance | Source fan-out, destination-port diversity, low-payload SYN patterns | Live stateful detector |
| DNS anomaly | Label entropy, length, digit ratio, record-type context | Live metadata detector |
| Beaconing | Inter-arrival regularity and small repeated sessions | Live temporal detector |
| Exfiltration | Outbound/inbound asymmetry with absolute-volume guard | Live baseline |
| Legitimate-service C2 | Multi-signal deviation on approved cloud/messaging services | Live correlation baseline |
| Correlation | Cross-detector evidence and deduplicated composites | Live engine |

## Temporal features

For a source (s) in a bounded window (W=300) seconds, the dashboard derives
flow rate (N/W), packet rate (P/W), byte rate (B/W), source/destination
entropy, destination-port fan-out, SYN-to-ACK ratio, and outbound/inbound byte
ratio. For event times (t_i), beacon regularity is represented by:

```text
IAT mean = mean(t_i - t_(i-1))
IAT CV   = stdev(IAT) / mean(IAT)
```

The store is capped at 50,000 events and evicts old observations. This keeps
latency and memory bounded instead of pretending an end-of-run batch report is
real time.

## Model governance

The repository-controlled artifact is evaluated on capture-grouped splits when
the source contains enough captures; otherwise the manifest records the
chronological fallback. Current local measurement is dataset-specific:

```text
train 120,000 | validation 60,000 | test 60,000
features 78  | test F1 0.6359    | test ROC-AUC 0.9055
```

These numbers are not a universal accuracy claim. They do not prove malware,
and no responsible system can promise 95–99% performance across unseen
networks without a representative, independently collected evaluation set.

## Safety and isolation

- Read-only mode is asserted in health and alert records.
- TLS/QUIC is represented by metadata only; no decryption is attempted.
- Uploads accept only bounded JSONL, NDJSON, CSV, or Parquet metadata.
- Payload-like keys, credentials, scripts, executables, and pickle files are rejected.
- Model artifacts are repository-contained and checksum-validated before loading.
- Response guidance is scoped to a source, flow, destination service, DNS client,
  or source/service pair; automatic enforcement is always false.

## Operational response

An alert is intelligence, not an instruction to shut down a company network.
The `containment_scope` field tells an authorized SOC which smallest boundary to
review. The operator corroborates with EDR, identity, DNS, firewall, and change
management telemetry, then applies an approved control outside NetSentinel.

## Throughput demonstration

The local metadata upload path is bounded to 20,000 records and reports
`events_per_second`. On the generated 449-record bundle, JSONL, CSV, and
Parquet replay complete locally while preserving `metadata_only=true` and
`read_only=true`. Production capacity must be re-measured on the target tap,
CPU, storage, and flow-export format.
