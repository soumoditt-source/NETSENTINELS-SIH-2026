# NetSentinel Plus documentation index

This folder contains the complete operator, engineering, security, and SIH
handoff material for the additive sidecar. Runtime code remains one level up;
the original NetSentinel application remains unchanged.

| Document | Use it for |
|---|---|
| [`STARTUP.md`](STARTUP.md) | PowerShell commands, provider setup, launch, judge flow, and stop procedure |
| [`KEY_SETUP.md`](KEY_SETUP.md) | Local-only credential setup and rotation guidance |
| [`ONNX_ENABLEMENT.md`](ONNX_ENABLEMENT.md) | Install and verify every local ONNX model |
| [`TECHNICAL.md`](TECHNICAL.md) | Architecture, API contract, data handling, and failure model |
| [`COMPARISON.md`](COMPARISON.md) | Original application versus additive sidecar capabilities |
| [`SIH_PRESENTATION.md`](SIH_PRESENTATION.md) | Full slide-by-slide SIH presentation writing and visual plan |

## Runtime files

The sidecar implementation is intentionally kept separate from documentation:

| Path | Responsibility |
|---|---|
| `../app.py` | FastAPI sidecar routes and read-only proxy to the original API |
| `../providers.py` | Validated, cache-backed provider and Mistral adapters |
| `../assessment.py` | C2 Temporal Evidence Convergence triage calculation |
| `../static/index.html` | Standalone Overview, IOC Lookup, and Alert Review menu |
| `../../../../launch_netsentinel_all.bat` | Original application plus sidecar orchestration |

## External provider boundary

AbuseIPDB, ThreatFox, VirusTotal, and URLhaus are optional metadata sources.
Mistral is an optional explanation layer. None is required for the local
detector, and none can modify its score. No provider integration accepts files,
downloads samples, executes content, decrypts payloads, probes targets, or
sends blocking commands.
