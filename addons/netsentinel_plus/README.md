# NetSentinel Plus

NetSentinel Plus is an additive sidecar. It reads the existing NetSentinel API
and provides a separate analyst menu for optional, metadata-only enrichment.

## What it adds

- Live read-only snapshot of the existing backend.
- Public IOC lookup through optional AbuseIPDB, ThreatFox, VirusTotal, and URLhaus credentials.
- Optional Mistral analyst brief generated from redacted alert evidence.
- Local validation, bounded response sizes, and cache-backed lookups.
- No executable uploads, sample downloads, payload decryption, callbacks, active probing, or blocking.

## What it does not change

The original `netsentinel/`, `frontend/`, `README.md`, configuration, models,
tests, and launch script are not imported into the startup path and are not
modified by this add-on. The original application continues to use port `8100`.

## Run

From the repository root:

```powershell
$env:NETSENTINEL_BACKEND_URL = "http://127.0.0.1:8100"
$env:ABUSEIPDB_API_KEY = ""
$env:THREATFOX_AUTH_KEY = ""
$env:VIRUSTOTAL_API_KEY = ""
$env:URLHAUS_AUTH_KEY = ""
$env:MISTRAL_API_KEY = ""
python -m uvicorn addons.netsentinel_plus.app:app --host 127.0.0.1 --port 8200
```

Or use the new root launcher:

```powershell
.\launch_netsentinel_plus.bat
```

For provider enrichment, revoke any credentials exposed outside your local
machine and create `addons/netsentinel_plus/.env.local` using
`KEY_SETUP.md`. That file is ignored by Git. The sidecar remains fully usable
without provider keys in offline-safe mode.

Open `http://127.0.0.1:8200`. The existing dashboard remains at
`http://127.0.0.1:5174` and the existing API remains at `http://127.0.0.1:8100`.

## Sidecar endpoints

| Method | Endpoint | Purpose |
|---|---|---|
| `GET` | `/api/addon/health` | Sidecar, backend, and provider status |
| `GET` | `/api/addon/live` | Existing health, alerts, temporal telemetry, and launch report |
| `GET` | `/api/addon/lookup?ip=...` | Safe IOC metadata lookup |
| `GET` | `/api/addon/alert/{id}/enrich` | Enrich one existing alert without changing its score |
| `GET` | `/api/addon/alert/{id}/brief` | Enrich and optionally generate a Mistral brief |

All credentials are read from environment variables and are never returned by
the status endpoint. Provider results are advisory; local detector output is
the authoritative decision.

The VirusTotal public API is restricted to metadata/hash lookups in this
sidecar; no executable is uploaded or downloaded. Mistral is used only for a
bounded analyst brief from redacted structured evidence. External provider
outages or rate limits never change the local detector score.
