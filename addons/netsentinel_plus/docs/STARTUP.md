# NetSentinel startup runbook

This runbook starts the original NetSentinel application and the additive
NetSentinel Plus console without changing the original startup path.

## Recommended one-command launch

Open PowerShell in the repository root:

```powershell
Set-Location "D:\PORT SCANNING CYS IP FLOW\testing-main"
.\launch_netsentinel_all.bat
```

The launcher runs the measured audit, starts or reuses the original backend on
`8100`, starts or reuses the original dashboard on `5174`, then starts the
additive analyst console on `8200`.

Open:

- Original dashboard: `http://127.0.0.1:5174`
- Additive analyst console: `http://127.0.0.1:8200`
- Additive API documentation: `http://127.0.0.1:8200/docs`

## Enable all local models

Before the first launch on a new machine, install the repository dependencies:

```powershell
Set-Location "D:\PORT SCANNING CYS IP FLOW\testing-main"
python -m pip install -r requirements.txt
```

The ONNX verification procedure and expected `12/12` health output are in
`ONNX_ENABLEMENT.md`.

The same launcher prints the measured train, validation, and test scorecard in
the terminal before the Plus console starts. The scorecard is read from the
current launch report and live backend health; it is not a promise of universal
malware accuracy.

## Provider setup

Rotate credentials that have been exposed outside the local machine. Create
`addons/netsentinel_plus/.env.local` using `KEY_SETUP.md`; never put real keys
in Git, screenshots, frontend code, or chat.

PowerShell setup without storing keys in the repository:

```powershell
Set-Location "D:\PORT SCANNING CYS IP FLOW\testing-main"
notepad .\addons\netsentinel_plus\.env.local
.\launch_netsentinel_all.bat
```

The local file should contain replacement credentials only:

```text
NETSENTINEL_BACKEND_URL=http://127.0.0.1:8100
ABUSEIPDB_API_KEY=your-new-key
THREATFOX_AUTH_KEY=your-new-key
VIRUSTOTAL_API_KEY=your-new-key
URLHAUS_AUTH_KEY=your-new-key-if-required
MISTRAL_API_KEY=your-new-key
MISTRAL_MODEL=mistral-small-latest
```

No provider key is required for the local detector or safe replay. The console
reports missing providers as offline-safe and never changes the local score.

## Judge flow

1. Run `launch_netsentinel_all.bat`.
2. Open the additive console and choose `Overview`.
3. Confirm the original backend is `ONLINE` and providers show only the
   intentionally configured count.
4. In the original dashboard, launch `mixed_enterprise` replay or load an
   authorized metadata-only PCAP/Zeek trace.
5. Return to `Alert review` in the additive console.
6. Use `Enrich` for IOC context or `Brief` for a Mistral analyst summary.
7. Keep the original alert confidence and local evidence as the decision
   authority.

## Stop

Close the two launch windows, or use PowerShell after checking the process
ownership:

```powershell
Get-NetTCPConnection -LocalPort 8100,5174,8200 -State Listen -ErrorAction SilentlyContinue |
  Select-Object LocalAddress,LocalPort,OwningProcess
```

Do not stop an unrelated process. Stop only the NetSentinel processes started
for this session from their own terminals with `Ctrl+C`.

## Safety boundary

NetSentinel is a passive, read-only network-forensics system. The workflow
accepts metadata and authorized PCAP/Zeek evidence only. It does not accept or
execute malware, download samples, decrypt payloads, probe live targets, send
commands, or block traffic.
