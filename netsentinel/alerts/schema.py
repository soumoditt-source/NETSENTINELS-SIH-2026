"""Versioned, evidence-first alert contract used at API boundaries."""

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class AlertSchema(BaseModel):
    """A metadata-only alert with explicit provenance and safety assertions."""

    model_config = ConfigDict(extra="allow")

    alert_id: str = ""
    schema_version: str = "1.1.0"
    created_at: float = 0.0
    first_seen: float | None = None
    last_seen: float | None = None
    flow_id: str | None = None
    related_flow_ids: list[str] = Field(default_factory=list)
    related_event_ids: list[str] = Field(default_factory=list)
    source_identity: str = "unknown"
    destination_identity: str = "unknown"
    domain: str | None = None
    service_family: str | None = None
    threat_class: str = "unknown"
    subtechnique: str | None = None
    threat_subtype: str | None = None
    severity: str = "low"
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    risk_score: float = Field(default=0.0, ge=0.0, le=1.0)
    status: str = "open"
    detector: str = "unknown"
    detector_method: str = "unknown"
    model_version: str = "1.0.0"
    supporting_evidence: list[str] = Field(default_factory=list)
    feature_snapshot: dict[str, Any] = Field(default_factory=dict)
    observed_protocol: str | None = None
    service_context: dict[str, Any] = Field(default_factory=dict)
    mitre_attack_techniques: list[str] = Field(default_factory=list)
    mitre_attack_mapping: dict[str, Any] = Field(default_factory=dict)
    possible_benign_explanations: list[str] = Field(default_factory=list)
    false_positive_notes: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    correlation_id: str | None = None
    read_only: bool = True
    payload_decrypted: bool = False
    recommended_defensive_next_step: str = "Review metadata evidence and corroborate with approved telemetry."
    containment_scope: dict[str, Any] = Field(default_factory=dict)
