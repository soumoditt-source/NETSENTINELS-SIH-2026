# Baseline versus NetSentinel Plus

This comparison describes what was added without changing the existing
application. It is intentionally factual and does not claim that the product
replaces commercial antivirus or a full SIEM.

## Capability comparison

| Capability | Existing NetSentinel | NetSentinel Plus |
|---|---|---|
| Passive flow analysis | Yes | Reads the existing result |
| Temporal threat detection | Yes | Displays current telemetry |
| PCAP/Zeek/metadata ingest | Yes | Does not duplicate ingest |
| Local ML and rule authority | Yes | Preserves the original score |
| IOC reputation context | Not required for operation | Optional provider enrichment |
| Human-readable AI brief | Local explanation workflow | Optional redacted Mistral brief |
| Analyst menu | Main command-center dashboard | Separate Overview, Lookup, Alert Review tabs |
| Credential handling | Local runtime configuration | Ignored `.env.local` and non-secret status |
| Startup | Original launcher | Unified additive launcher |
| Safety boundary | Read-only metadata pipeline | Same boundary; no payload operations |

## What changed

- A separate service was added under `addons/netsentinel_plus/`.
- The service reads existing alerts and temporal telemetry over HTTP.
- Safe public IOC validation happens before any optional provider request.
- Provider responses are advisory and cache-backed.
- Mistral is used only to explain structured evidence, never to classify or
  take action.
- A single launcher starts the original application first, then the sidecar.
- New documentation gives operators, judges, and developers one clear path.

## What deliberately did not change

The original `netsentinel/` package, `frontend/` package, model files,
configuration, root `README.md`, original tests, and original launch script are
not modified by the add-on. The old dashboard and API remain independently
usable if the sidecar is unavailable.

## Product value

The add-on improves analyst workflow rather than inflating detection claims:

1. **Context:** an analyst can corroborate an alert with current IOC sources.
2. **Clarity:** a redacted language-model brief turns structured evidence into
   readable investigation language.
3. **Safety:** provider failures cannot change local decisions or send network
   commands.
4. **Feasibility:** the sidecar can be deployed, tested, and removed without
   rewriting the monitoring enclave.
5. **Trust:** provenance, score immutability, and offline behavior are visible.

## Honest limitations

- Reputation services are incomplete, delayed, and sometimes rate-limited.
- A clean IOC result does not prove that traffic is benign.
- A language model cannot establish ground truth from metadata alone.
- Detection quality still depends on representative, independently held-out
  traffic and site-specific calibration.
- This system detects network behavior; it does not promise arbitrary file
  malware detection.

## Recommended SIH framing

Present the original NetSentinel pipeline as the detection product and Plus as
the optional analyst-enrichment layer. Demonstrate one alert from local
evidence to advisory context, then show that the score remains unchanged. This
is a stronger and more defensible story than claiming an external API makes
the classifier perfect.

