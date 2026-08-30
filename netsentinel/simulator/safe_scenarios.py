"""
netsentinel/simulator/safe_scenarios.py
========================================
Safe, offline-only scenario event generators.

ALL events are synthetic metadata records — no packets are transmitted,
no real C2 callbacks are made, no live malware is used.

Each generator produces canonical dict events compatible with FlowAnalyzer.
Every event includes a ``_ground_truth`` key so the replay lab can compare
detector output against the known label.

Design rules:
  - Distributions overlap between benign and malicious.
  - Jitter and noise are applied to avoid trivially-separable labels.
  - Hard-negative benign scenarios are included.
  - All randomness is seeded per scenario for reproducibility.
"""

from __future__ import annotations

import math
import random
import hashlib
from typing import Any, Iterator

# ── Private helpers ────────────────────────────────────────────────────────────

_INTERNAL_SUBNETS = ["10.0.{}.{}", "172.16.{}.{}", "192.168.{}.{}"]
_DOCUMENTATION_NETWORKS = ("198.51.100", "203.0.113", "192.0.2")
_CLOUD_DOMAINS = [
    "api.telegram.org", "discord.com", "onedrive.live.com",
    "drive.google.com", "teams.microsoft.com", "dropbox.com",
    "box.com", "slack.com", "zoom.us",
]
_CDN_DOMAINS = [
    "cdn.cloudflare.com", "akamaiedge.net", "fastly.net",
    "edgecastcdn.net", "cloudfront.net",
]
_BENIGN_DOMAINS = [
    "fonts.gstatic.com", "update.microsoft.com", "ocsp.digicert.com",
    "connectivity-check.ubuntu.com", "tiles.openstreetmap.org",
]


def _internal_ip(rng: random.Random) -> str:
    tmpl = rng.choice(_INTERNAL_SUBNETS)
    return tmpl.format(rng.randint(1, 30), rng.randint(2, 254))


def _external_ip(rng: random.Random) -> str:
    return f"{rng.choice(_DOCUMENTATION_NETWORKS)}.{rng.randint(1, 254)}"


def _synthetic_event_id(rng: random.Random, namespace: str) -> str:
    """Create a reproducible identifier without relying on host entropy."""

    return hashlib.sha256(f"{namespace}:{rng.random():.16f}".encode()).hexdigest()[:24]


def _synthetic_timestamp(rng: random.Random) -> float:
    """Return a deterministic timestamp in a fixed offline demonstration day."""

    return 1_700_000_000.0 + rng.uniform(0.0, 86_400.0)


def _jitter(rng: random.Random, value: float, pct: float = 0.15) -> float:
    return max(0.0, value * (1 + rng.gauss(0, pct)))


def _base_flow(src: str, dst: str, proto: int, packets: int, bytes_: int,
               duration_ms: float, rng: random.Random) -> dict[str, Any]:
    pps = (packets / (duration_ms / 1000)) if duration_ms > 0 else 0
    bps = (bytes_ / (duration_ms / 1000)) if duration_ms > 0 else 0
    return {
        "type": "flow",
        "source_ip": src,
        "dest_ip": dst,
        "observed_at": _synthetic_timestamp(rng),
        "flow_id": _synthetic_event_id(rng, f"flow:{src}:{dst}"),
        "features": {
            "Protocol": proto,
            "Flow Duration": duration_ms * 1000,     # microseconds
            "Total Fwd Packets": packets,
            "Total Backward Packets": max(1, int(packets * rng.uniform(0.2, 1.5))),
            "Fwd Packets Length Total": bytes_ * rng.uniform(0.4, 0.8),
            "Bwd Packets Length Total": bytes_ * rng.uniform(0.1, 0.5),
            "Flow Bytes/s": bps,
            "Flow Packets/s": pps,
            "Flow IAT Mean": _jitter(rng, duration_ms * 1000 / max(packets, 1), 0.2),
            "Flow IAT Std": _jitter(rng, 5000, 0.5),
            "SYN Flag Count": 0,
            "ACK Flag Count": packets,
            "PSH Flag Count": max(0, int(packets * 0.3)),
            "RST Flag Count": 0,
            "Destination Port": rng.randint(1024, 65535),
        },
    }


# ── PUBLIC GENERATORS ─────────────────────────────────────────────────────────

def benign_web_browsing(seed: int = 0, n: int = 10) -> Iterator[dict]:
    """Scenario 1: Normal HTTPS web browsing traffic. Hard negative."""
    rng = random.Random(seed)
    src = _internal_ip(rng)
    for _ in range(n):
        dst = _external_ip(rng)
        ev = _base_flow(src, dst, proto=6,
                        packets=rng.randint(10, 80),
                        bytes_=rng.randint(2000, 80000),
                        duration_ms=_jitter(rng, 3000, 0.4),
                        rng=rng)
        ev["features"]["Destination Port"] = rng.choice([80, 443])
        ev["_ground_truth"] = {"label": "benign", "scenario": "web_browsing"}
        ev["features"]["SYN Flag Count"] = 1
        ev["features"]["ACK Flag Count"] = rng.randint(8, 60)
        yield ev


def benign_software_update(seed: int = 1, n: int = 6) -> Iterator[dict]:
    """Scenario 2: Periodic SW update download. Hard negative vs beaconing."""
    rng = random.Random(seed)
    src = _internal_ip(rng)
    dst = _external_ip(rng)
    intervals = [_jitter(rng, 3600, 0.05) for _ in range(n)]  # ~1h intervals
    for interval in intervals:
        ev = _base_flow(src, dst, proto=6,
                        packets=rng.randint(500, 5000),
                        bytes_=rng.randint(5_000_000, 50_000_000),
                        duration_ms=_jitter(rng, 120_000, 0.2),
                        rng=rng)
        ev["features"]["Destination Port"] = 443
        ev["_ground_truth"] = {
            "label": "benign", "scenario": "software_update",
            "note": "Periodic but benign — do not flag as beacon",
        }
        yield ev


def benign_cloud_sync(seed: int = 2, n: int = 8) -> Iterator[dict]:
    """Scenario 3: Cloud backup / sync upload. Hard negative vs exfiltration."""
    rng = random.Random(seed)
    src = _internal_ip(rng)
    dst = _external_ip(rng)
    for _ in range(n):
        bytes_ = rng.randint(20_000_000, 200_000_000)
        ev = _base_flow(src, dst, proto=6,
                        packets=rng.randint(15000, 150000),
                        bytes_=bytes_,
                        duration_ms=_jitter(rng, 600_000, 0.3),
                        rng=rng)
        ev["features"]["Destination Port"] = 443
        ev["dest_domain"] = rng.choice(_CLOUD_DOMAINS)
        ev["_ground_truth"] = {
            "label": "benign", "scenario": "cloud_sync",
            "note": "Benign large upload to known cloud provider — approved service",
        }
        yield ev


def benign_messaging_periodic(seed: int = 3, n: int = 20) -> Iterator[dict]:
    """Scenario 4: Normal messaging-service traffic. Hard negative vs legit-service C2."""
    rng = random.Random(seed)
    src = _internal_ip(rng)
    dst = _external_ip(rng)
    for _ in range(n):
        ev = _base_flow(src, dst, proto=6,
                        packets=rng.randint(5, 30),
                        bytes_=rng.randint(300, 5000),
                        duration_ms=_jitter(rng, 800, 0.6),  # variable intervals
                        rng=rng)
        ev["features"]["Destination Port"] = 443
        ev["dest_domain"] = "api.telegram.org"
        ev["_ground_truth"] = {
            "label": "benign", "scenario": "normal_messaging",
            "note": "Normal messaging app usage — do not flag as C2",
        }
        yield ev


def syn_flood(seed: int = 10, n: int = 500) -> Iterator[dict]:
    """Scenario 11: SYN-flood-like metadata pattern."""
    rng = random.Random(seed)
    dst = _external_ip(rng)  # One target
    for _ in range(n):
        src = _external_ip(rng)   # Many spoofed sources
        ev = _base_flow(src, dst, proto=6,
                        packets=rng.randint(1, 3),
                        bytes_=rng.randint(40, 120),
                        duration_ms=_jitter(rng, 0.5, 0.5),
                        rng=rng)
        ev["features"]["SYN Flag Count"] = 1
        ev["features"]["ACK Flag Count"] = 0
        ev["features"]["PSH Flag Count"] = 0
        ev["features"]["Flow Packets/s"] = _jitter(rng, 50000, 0.3)
        ev["features"]["Flow Bytes/s"] = _jitter(rng, 6_000_000, 0.3)
        ev["features"]["Destination Port"] = 80
        ev["_ground_truth"] = {"label": "attack", "scenario": "syn_flood",
                                "threat_class": "DDoS", "subtype": "SYN Flood"}
        yield ev


def udp_flood(seed: int = 11, n: int = 400) -> Iterator[dict]:
    """Scenario 12: UDP-flood-like metadata pattern."""
    rng = random.Random(seed)
    src = _external_ip(rng)
    dst = _internal_ip(rng)
    for _ in range(n):
        ev = _base_flow(src, dst, proto=17,
                        packets=rng.randint(100, 1000),
                        bytes_=rng.randint(64000, 1_500_000),
                        duration_ms=_jitter(rng, 1.0, 0.3),
                        rng=rng)
        ev["features"]["Flow Packets/s"] = _jitter(rng, 200_000, 0.2)
        ev["features"]["Flow Bytes/s"] = _jitter(rng, 800_000_000, 0.2)
        ev["_ground_truth"] = {"label": "attack", "scenario": "udp_flood",
                                "threat_class": "DDoS", "subtype": "UDP Flood"}
        yield ev


def horizontal_scan(seed: int = 14, n_targets: int = 50) -> Iterator[dict]:
    """Scenario 15: Horizontal port scan — one port across many hosts."""
    rng = random.Random(seed)
    src = _internal_ip(rng)
    port = rng.randint(22, 8080)
    for _ in range(n_targets):
        dst = _external_ip(rng)
        ev = _base_flow(src, dst, proto=6,
                        packets=rng.randint(1, 3),
                        bytes_=rng.randint(40, 200),
                        duration_ms=_jitter(rng, 50, 0.8),
                        rng=rng)
        ev["features"]["SYN Flag Count"] = 1
        ev["features"]["ACK Flag Count"] = 0
        ev["features"]["RST Flag Count"] = rng.randint(0, 1)
        ev["features"]["Destination Port"] = port
        ev["_ground_truth"] = {
            "label": "attack", "scenario": "horizontal_scan",
            "threat_class": "Reconnaissance", "subtype": "Horizontal Scan",
        }
        yield ev


def vertical_scan(seed: int = 15, n_ports: int = 60) -> Iterator[dict]:
    """Scenario 16: Vertical scan — many ports on one host."""
    rng = random.Random(seed)
    src = _internal_ip(rng)
    dst = _external_ip(rng)
    ports = rng.sample(range(1, 65535), n_ports)
    for port in ports:
        ev = _base_flow(src, dst, proto=6,
                        packets=rng.randint(1, 2),
                        bytes_=rng.randint(40, 100),
                        duration_ms=_jitter(rng, 30, 1.0),
                        rng=rng)
        ev["features"]["SYN Flag Count"] = 1
        ev["features"]["ACK Flag Count"] = 0
        ev["features"]["Destination Port"] = port
        ev["_ground_truth"] = {
            "label": "attack", "scenario": "vertical_scan",
            "threat_class": "Reconnaissance", "subtype": "Vertical Scan",
        }
        yield ev


def slow_stealth_scan(seed: int = 16, n: int = 30) -> Iterator[dict]:
    """Scenario 17: Low-and-slow scan — sparse probes over long interval."""
    rng = random.Random(seed)
    src = _internal_ip(rng)
    ports = rng.sample(range(1, 10000), n)
    for port in ports:
        dst = _external_ip(rng)
        ev = _base_flow(src, dst, proto=6,
                        packets=1,
                        bytes_=rng.randint(40, 60),
                        duration_ms=_jitter(rng, 10, 0.5),
                        rng=rng)
        ev["features"]["SYN Flag Count"] = 1
        ev["features"]["ACK Flag Count"] = 0
        ev["features"]["Destination Port"] = port
        ev["_ground_truth"] = {
            "label": "attack", "scenario": "slow_stealth_scan",
            "threat_class": "Reconnaissance", "subtype": "Stealth Scan",
        }
        yield ev


def c2_beaconing(seed: int = 17, n: int = 30) -> Iterator[dict]:
    """Scenario 18: Periodic beacon-like behavior — regular check-ins."""
    rng = random.Random(seed)
    src = _internal_ip(rng)
    dst = _external_ip(rng)
    base_interval_ms = _jitter(rng, 60_000, 0.02)  # tight ~60s interval
    for i in range(n):
        ev = _base_flow(src, dst, proto=6,
                        packets=rng.randint(2, 6),
                        bytes_=rng.randint(200, 800),
                        duration_ms=_jitter(rng, base_interval_ms, 0.03),
                        rng=rng)
        ev["features"]["Destination Port"] = rng.choice([443, 8443, 4443])
        ev["_ground_truth"] = {
            "label": "attack", "scenario": "c2_beaconing",
            "threat_class": "C2 Beaconing",
            "evidence_hint": f"interval_ms={base_interval_ms:.0f}",
        }
        yield ev


def dga_like_dns(seed: int = 18, n: int = 25) -> Iterator[dict]:
    """Scenario 19: DGA-like domain DNS queries."""
    rng = random.Random(seed)
    src = _internal_ip(rng)

    def _dga_domain() -> str:
        length = rng.randint(12, 24)
        chars = "abcdefghijklmnopqrstuvwxyz0123456789"
        stem = "".join(rng.choices(chars, k=length))
        return f"{stem}.{rng.choice(['com', 'net', 'org', 'info'])}"

    for _ in range(n):
        domain = _dga_domain()
        ev = {
            "type": "dns",
            "source_ip": src,
            "observed_at": _synthetic_timestamp(rng),
            "flow_id": _synthetic_event_id(rng, f"dns:{src}:{domain}"),
            "domain": domain,
            "_ground_truth": {
                "label": "attack", "scenario": "dga_dns",
                "threat_class": "DGA",
            },
            "features": {},
        }
        yield ev


def dns_tunneling_like(seed: int = 19, n: int = 20) -> Iterator[dict]:
    """Scenario 20: DNS-tunneling-like metadata (long subdomain labels, TXT queries)."""
    rng = random.Random(seed)
    src = _internal_ip(rng)
    parent = f"legit{rng.randint(100,999)}.com"

    def _encoded_subdomain() -> str:
        b64chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        length = rng.randint(32, 63)
        return "".join(rng.choices(b64chars, k=length))

    for _ in range(n):
        sub = _encoded_subdomain()
        domain = f"{sub}.{parent}"
        ev = {
            "type": "dns",
            "source_ip": src,
            "observed_at": _synthetic_timestamp(rng),
            "flow_id": _synthetic_event_id(rng, f"dns-tunnel:{src}:{domain}"),
            "domain": domain,
            "dns_type": "TXT",
            "_ground_truth": {
                "label": "attack", "scenario": "dns_tunneling",
                "threat_class": "DNS Tunnel",
            },
            "features": {},
        }
        yield ev


def exfiltration_like(seed: int = 21, n: int = 5) -> Iterator[dict]:
    """Scenario 22: Exfiltration-like high outbound volume + asymmetry."""
    rng = random.Random(seed)
    src = _internal_ip(rng)
    dst = _external_ip(rng)
    for _ in range(n):
        bytes_out = rng.randint(50_000_000, 200_000_000)
        bytes_in = rng.randint(200, 2000)
        ev = _base_flow(src, dst, proto=6,
                        packets=rng.randint(40000, 200000),
                        bytes_=bytes_out,
                        duration_ms=_jitter(rng, 900_000, 0.2),
                        rng=rng)
        ev["features"]["Destination Port"] = 443
        ev["features"]["Fwd Packets Length Total"] = bytes_out
        ev["features"]["Bwd Packets Length Total"] = bytes_in
        # Inject host_state-compatible fields for exfil detector
        ev["_bytes_out"] = bytes_out
        ev["_bytes_in"] = bytes_in
        ev["_ground_truth"] = {
            "label": "attack", "scenario": "exfiltration",
            "threat_class": "Data Exfiltration",
            "note": f"ratio={bytes_out/max(bytes_in,1):.1f}x",
        }
        yield ev


def suspicious_legit_service_c2(seed: int = 23, n_checkins: int = 18) -> Iterator[dict]:
    """
    Scenario 24: Full suspicious legitimate-service C2 behavioral chain.
    Pattern: DNS anomaly → periodic check-ins → anomalous upload.
    This is the project's UNIQUE differentiator.
    """
    rng = random.Random(seed)
    src = _internal_ip(rng)
    cloud_dst = _external_ip(rng)
    service = rng.choice(_CLOUD_DOMAINS)

    # Step 1: DNS anomaly precursor
    domain_stem = "".join(rng.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=14))
    dns_ev = {
        "type": "dns",
        "source_ip": src,
        "observed_at": _synthetic_timestamp(rng),
        "flow_id": _synthetic_event_id(rng, f"service-dns:{src}:{service}"),
        "domain": f"{domain_stem}.{service.split('.', 1)[-1]}",
        "_ground_truth": {
            "label": "attack", "scenario": "legit_service_c2",
            "stage": "dns_anomaly", "threat_class": "Legitimate-Service C2",
        },
        "features": {},
    }
    yield dns_ev

    # Step 2: Periodic check-ins (tight interval)
    base_interval = _jitter(rng, 100_000, 0.02)   # ~100s very tight
    for i in range(n_checkins):
        ev = _base_flow(src, cloud_dst, proto=6,
                        packets=rng.randint(2, 5),
                        bytes_=rng.randint(150, 600),
                        duration_ms=_jitter(rng, base_interval, 0.02),
                        rng=rng)
        ev["dest_domain"] = service
        ev["features"]["Destination Port"] = 443
        ev["_ground_truth"] = {
            "label": "attack", "scenario": "legit_service_c2",
            "stage": "periodic_checkin", "threat_class": "Legitimate-Service C2",
            "evidence": f"interval={base_interval:.0f}ms interval_jitter=2%",
        }
        yield ev

    # Step 3: Anomalous upload (command response / data exfil via service)
    bytes_out = rng.randint(8_000_000, 40_000_000)
    bytes_in = rng.randint(100, 500)
    upload_ev = _base_flow(src, cloud_dst, proto=6,
                            packets=rng.randint(6000, 30000),
                            bytes_=bytes_out,
                            duration_ms=_jitter(rng, 120_000, 0.15),
                            rng=rng)
    upload_ev["dest_domain"] = service
    upload_ev["features"]["Destination Port"] = 443
    upload_ev["features"]["Fwd Packets Length Total"] = bytes_out
    upload_ev["features"]["Bwd Packets Length Total"] = bytes_in
    upload_ev["_bytes_out"] = bytes_out
    upload_ev["_bytes_in"] = bytes_in
    upload_ev["_ground_truth"] = {
        "label": "attack", "scenario": "legit_service_c2",
        "stage": "anomalous_upload", "threat_class": "Legitimate-Service C2",
        "note": "Upload follows check-ins to legitimate cloud service",
    }
    yield upload_ev


def mixed_enterprise_replay(seed: int = 99, n_total: int = 200) -> Iterator[dict]:
    """
    Scenario 25: Realistic mixed enterprise traffic — benign + attacks interleaved.
    Proportions: 70% benign, 30% attack (realistic enterprise ratio).
    """
    rng = random.Random(seed)
    # Collect all events from individual scenarios
    events: list[dict] = []
    events.extend(benign_web_browsing(seed, n=60))
    events.extend(benign_software_update(seed + 1, n=4))
    events.extend(benign_cloud_sync(seed + 2, n=6))
    events.extend(benign_messaging_periodic(seed + 3, n=15))
    events.extend(horizontal_scan(seed + 4, n_targets=25))
    events.extend(c2_beaconing(seed + 5, n=20))
    events.extend(dga_like_dns(seed + 6, n=10))
    events.extend(exfiltration_like(seed + 7, n=3))
    events.extend(suspicious_legit_service_c2(seed + 8, n_checkins=10))
    # Shuffle with seed
    rng.shuffle(events)
    for ev in events[:n_total]:
        yield ev
