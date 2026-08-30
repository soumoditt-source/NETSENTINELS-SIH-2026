# Local provider key setup

The provider credentials are intentionally not part of the repository. The
keys previously pasted into chat must be revoked and replaced because they are
considered exposed.

Create this file locally as:

```text
addons/netsentinel_plus/.env.local
```

Use replacement credentials supplied by each provider:

```env
NETSENTINEL_BACKEND_URL=http://127.0.0.1:8100
ABUSEIPDB_API_KEY=replace-with-a-new-abuseipdb-key
THREATFOX_AUTH_KEY=replace-with-a-new-threatfox-key
VIRUSTOTAL_API_KEY=replace-with-a-new-virustotal-key
URLHAUS_AUTH_KEY=replace-with-a-urlhaus-key-if-required
MISTRAL_API_KEY=replace-with-a-new-mistral-key
MISTRAL_MODEL=mistral-small-latest
NETSENTINEL_INTEL_TIMEOUT_S=4
NETSENTINEL_INTEL_CACHE_TTL_S=900
```

Do not reuse one provider's credential for another provider unless that
provider explicitly documents it. Do not paste keys into chat, commit them,
put them in screenshots, or place them in frontend code.

The launcher loads this file only into the local process environment. The
status page reports whether a provider is configured, never the key itself.
Missing keys are a supported offline mode; local NetSentinel detection does
not depend on external services.

