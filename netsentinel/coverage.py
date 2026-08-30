"""Defensible network-threat coverage for the read-only observation boundary.

This catalog is deliberately capability-based. ``active`` means a local
metadata detector is wired into the pipeline; it does not mean perfect recall.
``partial`` means flow/DNS/TLS metadata can raise suspicion but needs another
sensor or human review. ``out_of_scope`` requires endpoint or payload data.
"""

from collections import Counter
from typing import Any, TypedDict


class CoverageItem(TypedDict):
    family: str
    name: str
    status: str
    techniques: list[str]
    detectors: list[str]
    observed_signals: list[str]
    limitation: str
    test_scenarios: list[str]


COVERAGE_MATRIX: tuple[CoverageItem, ...] = (
    {
        "family": "Availability",
        "name": "Direct TCP SYN and UDP flood",
        "status": "active",
        "techniques": ["T1498", "T1498.001"],
        "detectors": ["VolumetricFloodRuleDetector", "CICIDSXGBoostDetector"],
        "observed_signals": ["packet rate", "SYN/ACK imbalance", "bytes per second", "source entropy"],
        "limitation": "Capacity impact and upstream filtering still require network operations telemetry.",
        "test_scenarios": ["syn_flood", "udp_flood"],
    },
    {
        "family": "Availability",
        "name": "Reflection or amplification pattern",
        "status": "partial",
        "techniques": ["T1498", "T1498.002"],
        "detectors": ["VolumetricFloodRuleDetector", "CorrelationEngine"],
        "observed_signals": ["fan-in", "source entropy", "response/request asymmetry", "burst rate"],
        "limitation": "Attribution to a specific reflector needs resolver/service context and upstream logs.",
        "test_scenarios": ["udp_flood"],
    },
    {
        "family": "Availability",
        "name": "ICMP, protocol, and application-rate denial of service",
        "status": "partial",
        "techniques": ["T1498"],
        "detectors": ["CICIDSXGBoostDetector", "VolumetricFloodRuleDetector"],
        "observed_signals": ["protocol mix", "flow rate", "short flows", "destination concentration"],
        "limitation": "Application exhaustion and service health are not visible from flow metadata alone.",
        "test_scenarios": [],
    },
    {
        "family": "Reconnaissance",
        "name": "Horizontal and vertical port scanning",
        "status": "active",
        "techniques": ["T1046"],
        "detectors": ["ReconnaissanceRuleDetector", "CorrelationEngine"],
        "observed_signals": ["unique destinations", "unique ports", "SYN-only ratio", "time-window fan-out"],
        "limitation": "A single sparse observation can be ambiguous; longer windows and asset context improve confidence.",
        "test_scenarios": ["horizontal_scan", "vertical_scan", "port_scan"],
    },
    {
        "family": "Reconnaissance",
        "name": "Low-and-slow, distributed, and service enumeration",
        "status": "partial",
        "techniques": ["T1046", "T1595"],
        "detectors": ["ReconnaissanceRuleDetector", "TemporalForensics"],
        "observed_signals": ["long-window fan-out", "failed connection shape", "destination diversity"],
        "limitation": "Distributed attribution needs fleet-wide identity and longer retention than the bounded demo window.",
        "test_scenarios": ["slow_stealth_scan", "horizontal_scan"],
    },
    {
        "family": "Command and control",
        "name": "Periodic beaconing over common services",
        "status": "active",
        "techniques": ["T1071", "T1071.001", "T1071.005"],
        "detectors": ["BeaconingRuleDetector", "CorrelationEngine"],
        "observed_signals": ["inter-arrival CV", "periodicity", "destination concentration", "small repeated flows"],
        "limitation": "Approved keepalives, updates, and messaging clients are hard negatives and require allowlist context.",
        "test_scenarios": ["beaconing", "legit_service_c2"],
    },
    {
        "family": "Command and control",
        "name": "DNS-based C2 and DNS tunneling",
        "status": "active",
        "techniques": ["T1071.004", "T1048"],
        "detectors": ["DNSAnomalyRuleDetector", "CorrelationEngine"],
        "observed_signals": ["label length", "character entropy", "query volume", "record type"],
        "limitation": "DNS telemetry must include query names and response context; encrypted DNS reduces visibility.",
        "test_scenarios": ["dga", "dns_tunnel"],
    },
    {
        "family": "Command and control",
        "name": "DGA and dynamic-resolution infrastructure",
        "status": "active",
        "techniques": ["T1568", "T1568.001", "T1568.002", "T1568.003"],
        "detectors": ["DNSAnomalyRuleDetector"],
        "observed_signals": ["domain entropy", "n-gram-shaped anomaly", "NXDOMAIN ratio", "resolution churn"],
        "limitation": "DGA suspicion is not domain reputation or malware-family attribution.",
        "test_scenarios": ["dga"],
    },
    {
        "family": "Command and control",
        "name": "Fast flux DNS and fallback resolution",
        "status": "partial",
        "techniques": ["T1568.001", "T1568"],
        "detectors": ["DNSAnomalyRuleDetector", "TemporalForensics"],
        "observed_signals": ["one domain to many IPs", "short-lived resolutions", "destination churn"],
        "limitation": "Authoritative DNS TTL and resolver history are not currently retained by the flow schema.",
        "test_scenarios": [],
    },
    {
        "family": "Command and control",
        "name": "Legitimate-service and web-service abuse",
        "status": "active",
        "techniques": ["T1102", "T1071.001"],
        "detectors": ["LegitimateServiceC2Detector", "CorrelationEngine"],
        "observed_signals": ["periodicity", "cloud destination", "upload asymmetry", "DNS precursor"],
        "limitation": "Service identity alone is never treated as malicious; authorization context is required.",
        "test_scenarios": ["legit_service_c2", "messaging", "cloud_sync"],
    },
    {
        "family": "Command and control",
        "name": "Encrypted TLS/QUIC and non-standard-port C2 metadata",
        "status": "partial",
        "techniques": ["T1573", "T1571", "T1095"],
        "detectors": ["CICIDSXGBoostDetector", "TemporalForensics"],
        "observed_signals": ["flow size sequence", "timing", "port novelty", "directional asymmetry"],
        "limitation": "No payload decryption, certificate verdict, process identity, or endpoint verdict is available.",
        "test_scenarios": [],
    },
    {
        "family": "Command and control",
        "name": "Proxy, relay, peer-to-peer, and tunnel behavior",
        "status": "partial",
        "techniques": ["T1090", "T1090.001", "T1095"],
        "detectors": ["CorrelationEngine", "TemporalForensics"],
        "observed_signals": ["multi-hop fan-out", "unusual protocol mix", "stable relay timing"],
        "limitation": "Proxy identity and application semantics require endpoint, proxy, or encrypted-session context.",
        "test_scenarios": [],
    },
    {
        "family": "Exfiltration",
        "name": "Large outbound transfer and asymmetric flow volume",
        "status": "active",
        "techniques": ["T1041", "T1048"],
        "detectors": ["ExfiltrationBaselineDetector", "CorrelationEngine"],
        "observed_signals": ["outbound/inbound byte ratio", "transfer size", "destination novelty", "burst shape"],
        "limitation": "A sanctioned backup can look identical without data classification and business context.",
        "test_scenarios": ["exfiltration", "cloud_sync"],
    },
    {
        "family": "Exfiltration",
        "name": "DNS, web-service, cloud-storage, and alternate-protocol exfiltration",
        "status": "partial",
        "techniques": ["T1048", "T1048.003", "T1567", "T1567.002"],
        "detectors": ["DNSAnomalyRuleDetector", "ExfiltrationBaselineDetector", "LegitimateServiceC2Detector"],
        "observed_signals": ["encoded-looking labels", "upload asymmetry", "cloud destination", "request volume"],
        "limitation": "Content classification is intentionally absent; metadata can prioritize investigation only.",
        "test_scenarios": ["dns_tunnel", "exfiltration", "cloud_sync"],
    },
    {
        "family": "Initial access",
        "name": "Vulnerability scanning and exposed-service probing",
        "status": "partial",
        "techniques": ["T1595", "T1046"],
        "detectors": ["ReconnaissanceRuleDetector", "TemporalForensics"],
        "observed_signals": ["sequential service attempts", "port breadth", "failed-flow pattern"],
        "limitation": "The system cannot confirm a vulnerability or exploit success from one-way flow metadata.",
        "test_scenarios": ["port_scan"],
    },
    {
        "family": "Initial access",
        "name": "Brute-force and password-spraying network shape",
        "status": "partial",
        "techniques": ["T1110", "T1110.001", "T1110.003"],
        "detectors": ["TemporalForensics", "CorrelationEngine"],
        "observed_signals": ["repeated short sessions", "many account-facing destinations", "failure-like cadence"],
        "limitation": "Authentication success/failure and account identity must come from application or identity logs.",
        "test_scenarios": [],
    },
    {
        "family": "Lateral movement",
        "name": "Remote-service fan-out across SMB, RDP, SSH, WinRM, or database ports",
        "status": "partial",
        "techniques": ["T1021", "T1046"],
        "detectors": ["ReconnaissanceRuleDetector", "CorrelationEngine"],
        "observed_signals": ["internal destination fan-out", "service-port concentration", "new east-west edges"],
        "limitation": "The flow layer cannot see credentials, commands, or successful remote execution.",
        "test_scenarios": ["horizontal_scan", "vertical_scan"],
    },
    {
        "family": "Protocol abuse",
        "name": "Spoofed-source, fragmented, malformed, or covert protocol traffic",
        "status": "partial",
        "techniques": ["T1498", "T1095"],
        "detectors": ["VolumetricFloodRuleDetector", "CICIDSXGBoostDetector"],
        "observed_signals": ["source entropy", "flag inconsistency", "packet-size sequence", "protocol mix"],
        "limitation": "Header anomalies are indicators, not proof of spoofing or a crafted exploit.",
        "test_scenarios": ["syn_flood", "udp_flood"],
    },
    {
        "family": "Endpoint-only malware behavior",
        "name": "RATs, worms, botnet families, droppers, and malware-family attribution",
        "status": "out_of_scope",
        "techniques": ["T1059", "T1105", "T1071"],
        "detectors": [],
        "observed_signals": ["only resulting network metadata may be visible"],
        "limitation": "A flow-only system cannot identify a malware file, process, family, or infection without endpoint evidence.",
        "test_scenarios": [],
    },
    {
        "family": "Endpoint-only malware behavior",
        "name": "Living-off-the-land, process injection, fileless execution, and persistence",
        "status": "out_of_scope",
        "techniques": ["T1055", "T1218", "T1547"],
        "detectors": [],
        "observed_signals": ["possibly correlated outbound timing or destinations"],
        "limitation": "Process trees, memory, command lines, files, registry, and persistence are not present in unidirectional flow input.",
        "test_scenarios": [],
    },
    {
        "family": "Endpoint-only malware behavior",
        "name": "Ransomware, destructive impact, exploit payloads, and local evasion",
        "status": "out_of_scope",
        "techniques": ["T1486", "T1490", "T1562"],
        "detectors": [],
        "observed_signals": ["network side effects may be investigated"],
        "limitation": "NetSentinel is not an antivirus, sandbox, exploit detector, or Defender replacement.",
        "test_scenarios": [],
    },
)


def get_coverage() -> dict[str, Any]:
    """Return the current, explicit coverage contract for API and UI use."""

    counts = Counter(item["status"] for item in COVERAGE_MATRIX)
    return {
        "as_of": "2026-08-30",
        "framework": "MITRE ATT&CK Enterprise technique IDs reviewed on 2026-08-30",
        "scope": "Passive, read-only IP/network metadata from PCAP, Zeek, or safe replay",
        "taxonomy_note": "This is a major-family coverage map, not an exhaustive malware catalog or a universal detection guarantee.",
        "counts": {key: counts.get(key, 0) for key in ("active", "partial", "out_of_scope")},
        "items": [dict(item) for item in COVERAGE_MATRIX],
    }
