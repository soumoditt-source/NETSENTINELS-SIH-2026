"""Strict canonical records shared by ingestion, replay, and data tooling."""

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

SCHEMA_VERSION = "1.0.0"
SourceType = Literal["pcap", "zeek", "netflow", "simulator"]
CanonicalLabel = Literal[
    "benign",
    "ddos",
    "reconnaissance",
    "botnet_or_c2_like",
    "dns_anomaly",
    "encrypted_anomaly",
    "exfiltration_like",
    "other_attack",
    "unknown",
]


class CanonicalBase(BaseModel):
    """Base contract with strict extra-field handling for exported records."""

    model_config = ConfigDict(extra="allow", str_strip_whitespace=True)
    schema_version: str = SCHEMA_VERSION
    dataset_source: str = "unknown"
    capture_id: str = "unknown"
    scenario_id: str | None = None


class CanonicalFlowEvent(CanonicalBase):
    """A metadata-only bidirectional flow record."""

    event_id: str
    observed_at: datetime | None = None
    flow_id: str
    src_identity: str
    dst_identity: str
    src_port: int = Field(ge=0, le=65535)
    dst_port: int = Field(ge=0, le=65535)
    protocol: str
    direction: str = "unknown"
    duration_ms: float = Field(default=0.0, ge=0)
    fwd_packets: int = Field(default=0, ge=0)
    rev_packets: int = Field(default=0, ge=0)
    fwd_bytes: int = Field(default=0, ge=0)
    rev_bytes: int = Field(default=0, ge=0)
    packets_per_second: float = Field(default=0.0, ge=0)
    bytes_per_second: float = Field(default=0.0, ge=0)
    tcp_flags: str | None = None
    flow_state: str | None = None
    original_label: str | None = None
    canonical_label: CanonicalLabel = "unknown"
    label_confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    is_synthetic: bool = False

    @field_validator("protocol", "direction")
    @classmethod
    def non_empty(cls, value: str) -> str:
        if not value:
            raise ValueError("metadata field cannot be empty")
        return value


class CanonicalDnsEvent(CanonicalBase):
    """A DNS metadata record with no query payload contents beyond the name."""

    event_id: str
    observed_at: datetime | None = None
    client_identity: str
    resolver_identity: str | None = None
    query_name: str
    registered_domain: str | None = None
    query_type: str = "A"
    response_code: str | None = None
    answer_count: int = Field(default=0, ge=0)
    ttl: float | None = Field(default=None, ge=0)
    query_length: int = Field(default=0, ge=0)
    label_count: int = Field(default=0, ge=0)
    entropy: float = Field(default=0.0, ge=0)
    digit_ratio: float = Field(default=0.0, ge=0, le=1)
    ngram_score: float | None = None
    nxdomain: bool = False


class CanonicalEncryptedMetadataEvent(CanonicalBase):
    """TLS/QUIC handshake metadata; encrypted payloads are never represented."""

    event_id: str
    observed_at: datetime | None = None
    flow_id: str
    tls_version: str | None = None
    sni: str | None = None
    alpn: str | None = None
    ja3: str | None = None
    ja3s: str | None = None
    ja4: str | None = None
    cipher_count: int | None = Field(default=None, ge=0)
    extension_count: int | None = Field(default=None, ge=0)
    certificate_fields_if_observed: dict[str, Any] = Field(default_factory=dict)
    quic_version: str | None = None
    packet_size_summary: dict[str, float] = Field(default_factory=dict)
    timing_summary: dict[str, float] = Field(default_factory=dict)
    destination_identity: str
    payload_decrypted: bool = False


class BehaviorWindow(CanonicalBase):
    """Aggregated source behavior used by transparent correlation logic."""

    window_id: str
    window_start: datetime
    window_end: datetime
    source_identity: str
    destination_identity: str | None = None
    service_family: str | None = None
    unique_destinations: int = Field(default=0, ge=0)
    unique_ports: int = Field(default=0, ge=0)
    unique_domains: int = Field(default=0, ge=0)
    source_entropy: float = Field(default=0.0, ge=0)
    destination_entropy: float = Field(default=0.0, ge=0)
    packet_rate: float = Field(default=0.0, ge=0)
    byte_rate: float = Field(default=0.0, ge=0)
    outbound_inbound_ratio: float = Field(default=0.0, ge=0)
    periodicity_score: float = Field(default=0.0, ge=0, le=1)
    recurrence_count: int = Field(default=0, ge=0)
    fingerprint_rarity: float = Field(default=0.0, ge=0, le=1)
    destination_rarity: float = Field(default=0.0, ge=0, le=1)
    local_baseline_deviation: float = 0.0
    peer_group_deviation: float = 0.0
    supporting_event_ids: list[str] = Field(default_factory=list)
