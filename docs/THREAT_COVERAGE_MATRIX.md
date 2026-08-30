# Threat coverage matrix

**Review date:** 2026-08-30  
**Boundary:** unidirectional, read-only IP/network metadata from PCAP, Zeek
records, or the repository safe replay.

## The honest answer

No flow-only product can recognize every malware family or every historical IP
attack. NetSentinel can identify behavior that leaves a useful network shape;
it cannot see a file, process, memory injection, local persistence, exploit
payload, or decrypted content. The product therefore reports three states:

- **Active:** a local detector is wired into the streaming pipeline.
- **Partial:** metadata can prioritize a case, but endpoint, DNS, identity, or
  asset context is required for confirmation.
- **Endpoint-only:** the requested behavior is not inferable from flow metadata.

The matrix is a major-family coverage contract, not a promise of 100% recall.
Each alert must still be evaluated with the measured validation report and the
operator's environment context.

## Coverage summary

The current machine-readable catalog is `netsentinel/coverage.py` and is
available at `GET /api/coverage`. The single-page dashboard renders the same
records under **Threat coverage contract**, so the UI cannot drift from the
documented backend capability.

| Area | Active or partial signals | Current status |
|---|---|---|
| Availability | TCP SYN/UDP rate, source entropy, SYN/ACK imbalance, burst rate, fan-in | Active for direct flood; partial for reflection and application exhaustion |
| Reconnaissance | Horizontal/vertical fan-out, port diversity, SYN-only and failed-flow shape | Active for common port-scan shape; partial for sparse/distributed scanning |
| C2 | Inter-arrival variation, periodicity, destination concentration, DNS context, service correlation | Active for beacon-like and legitimate-service patterns; partial for proxies, P2P, and encrypted semantics |
| DNS | Query length, entropy, record type, NXDOMAIN-like context, resolution churn | Active for DGA-like metadata; partial for fast flux and encrypted DNS |
| Exfiltration | Outbound/inbound ratio, transfer size, upload burst, destination novelty | Active for asymmetric transfer; partial when sanctioned backups or cloud storage look similar |
| Lateral movement | East-west service fan-out and remote-service port patterns | Partial; no proof of credential use or successful remote execution |
| Endpoint malware | RAT/worm family, ransomware, LOLBins, process injection, fileless execution, persistence | Endpoint-only; intentionally not claimed by this product |

## ATT&CK alignment

Technique IDs are reviewed against the [MITRE ATT&CK Enterprise technique
catalog](https://attack.mitre.org/), including Network Denial of Service
`T1498`, Network Service Scanning `T1046`, Application Layer Protocol `T1071`,
Dynamic Resolution `T1568`, Encrypted Channel `T1573`, and Exfiltration
techniques. The catalog records the exact IDs per row and keeps the source
links here as the maintenance reference.

MITRE's current detection guidance distinguishes network traffic flow from
endpoint process evidence. That distinction is why a suspicious encrypted
flow is a useful investigation signal, but not proof that a malware file or
payload is present.

## Operational use

1. Start the safe replay and watch the rolling temporal features.
2. Open the coverage panel and filter **Active**, **Partial**, or
   **Endpoint-only**.
3. Use `reports/launch/launch_report.json` for binary `0=benign, 1=attack`
   metrics rather than a dashboard confidence value as a benchmark.
4. Correlate partial cases with authorized endpoint, DNS, identity, or asset
   telemetry before containment.

The response model is advisory and scoped to a source, flow pair, or service;
it never issues a block command from the read-only enclave.
