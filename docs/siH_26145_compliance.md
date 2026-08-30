# SIH 26145 compliance matrix

This matrix separates implemented behavior from capabilities that still need
real-data evidence.

| Requirement | Implementation | Test / demo | Status | Limitation |
|---|---|---|---|---|
| Read-only ingest | `netsentinel/config.py`, ingest adapters, API response flags | adapter and API tests; safe replay | Implemented | Live capture depends on host permissions |
| No payload decryption | flow extractor stores sizes/headers only; encrypted detector consumes metadata | schema assertions; alert safety fields | Implemented | Metadata cannot prove malware |
| Streaming | `PacketProcessor`, `StateManager`, `replay_engine.py` | replay and TTL tests | Implemented | State policy is per-source and in-memory |
| Throughput evidence | `netsentinel/evaluation/run_benchmark.py` | run benchmark locally | Implemented measurement path | No universal laptop rate is claimed |
| Standard alert schema | `netsentinel/alerts/schema.py`, `AlertManager` | schema and alert tests | Implemented | API still returns compatibility fields |
| DDoS | optional existing ONNX wrapper plus pipeline guard | model health and replay | Partial | Artifact provenance must be verified |
| Beaconing | optional existing sequence wrapper | model health and replay | Partial | Baseline benchmark records misses |
| DGA / DNS tunnel | optional existing wrapper and entropy gate | safe DNS replay | Partial | CIC-IDS2017 is not a DNS-label dataset |
| Encrypted metadata | optional wrapper; decryption disabled | metadata-only schema test | Partial | No malware certainty from metadata |
| Reconnaissance | `ReconnaissanceRuleDetector` | positive, negative, hard-negative tests | Implemented baseline | Approved scanners can trigger |
| Exfiltration-like behavior | `ExfiltrationBaselineDetector` | asymmetry and cloud-sync tests | Implemented baseline | Backup jobs need context |
| Legitimate-service correlation | `LegitimateServiceC2Detector`, `CorrelationEngine` | sequence and deduplication tests | Implemented baseline | Service identity alone never alerts |
| CIC-IDS2017 factory | `tools/datasets/cicids2017_factory.py` | `test_dataset_factory.py` | Implemented | Requires user-provided source files |
| Supervised training | `build_training_artifacts.py` | run after preparation | Implemented path | No artifact is claimed before execution |

The project must not be presented as 100% accurate, universally trained, or
able to prevent attacks. It produces prioritized read-only intelligence for
human verification.
