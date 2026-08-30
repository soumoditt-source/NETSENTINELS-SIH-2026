# Capability Comparison

This is a capability map, not a claim that one product is universally better.
NetSentinel and endpoint antivirus observe different parts of an attack.

| Capability | NetSentinel | Microsoft Defender for Endpoint | Zeek / Suricata-style stack |
|---|---|---|---|
| Primary vantage point | Passive one-way flow/metadata enclave | Endpoint process, file, memory, identity, and network telemetry | Network protocol logs and/or signatures |
| File malware classification | Not provided | Core capability | Not provided by default |
| Living-off-the-land process context | Not visible from flow-only input | Process-tree and behavior context | Not visible unless an endpoint source is added |
| DDoS / port fan-out | Temporal flow and stateful detectors | Not the primary passive-tap use case | Strong protocol/signature foundation; tuning is required |
| Beaconing and service abuse | Timing, asymmetry, DNS, and correlation | Can correlate with endpoint activity | Logs/features are available; correlation is deployment-specific |
| Encrypted traffic | Metadata only; no decryption | Endpoint and cloud context may add evidence | Metadata/log visibility depends on sensors |
| Blocking | Never; read-only by design | Can block/contain when policy and mode allow | Depends on deployment; inline controls may block |
| Explainability | Versioned evidence and temporal features | Vendor detections and investigation graph | Rule/log evidence, plus local analytics |
| Air-gapped/data-diode fit | Designed for it | Requires endpoint connectivity and onboarding | Strong fit for passive sensors |

Microsoft documents Defender network protection as blocking malicious or
suspicious destinations and documents behavioral blocking/containment using
endpoint behavior and process trees. Those are strengths NetSentinel does not
attempt to reproduce. NetSentinel's complementary value is continuous passive
visibility across a one-way monitoring enclave, especially when endpoint
execution context is unavailable.

## Defensible differentiator

The useful claim is not “better than Defender.” It is:

> NetSentinel adds explainable, temporal, metadata-only network intelligence in
> a read-only enclave, and hands a narrowly scoped case to the existing SOC.

Its strongest prototype differentiator is legitimate-service correlation: it
does not blacklist Telegram, OneDrive, Teams, or Google Drive; it looks for a
combination of regular check-ins, asymmetry, DNS precursor, and upload burst.

## How to prove improvement

Use a fixed, held-out, capture-separated evaluation set and report precision,
recall, F1, PR-AUC, alert latency, false positives per GB, and throughput. Run
the same authorized lab session through each tool where the tool supports that
input. Do not compare NetSentinel's network-flow F1 with an antivirus file
verdict; that would be an invalid experiment. Publish dataset versions, label
policy, exclusions, thresholds, and failures.

## Sources

- [Microsoft network protection](https://learn.microsoft.com/en-us/defender-endpoint/network-protection)
- [Microsoft behavioral blocking and containment](https://learn.microsoft.com/en-us/defender-endpoint/behavioral-blocking-containment)
- [Microsoft client behavioral blocking](https://learn.microsoft.com/en-us/defender-endpoint/client-behavioral-blocking)
- [CIC-IDS2017](https://www.unb.ca/cic/datasets/ids-2017.html)
- [MITRE ATT&CK](https://attack.mitre.org/)
- [Stratosphere CTU-13 datasets](https://www.stratosphereips.org/datasets)
