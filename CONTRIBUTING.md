# Contributing

- Keep runtime offline by default and preserve `read_only_mode` behavior.
- Add tests with every detector or schema change.
- Do not add live attack tooling, credentials, malware, or payloads.
- Do not call rules trained ML models.
- Record real dataset hashes and split methodology; never fabricate metrics.
- Run focused tests first, then the application build when applicable.
