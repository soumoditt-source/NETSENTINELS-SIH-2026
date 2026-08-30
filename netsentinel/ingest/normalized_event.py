from pydantic import BaseModel, Field
from typing import Optional, Dict, Any
import uuid
import time

class NormalizedEvent(BaseModel):
    """
    Normalized streaming event schema.
    Strictly enforced metadata-only definition.
    """
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    observed_at: float = Field(default_factory=time.time)
    source_type: str = Field(..., description="pcap | zeek | netflow | simulator")
    flow_id: str
    
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    
    direction: str = Field(default="unknown")
    packets: int
    bytes: int
    duration: float
    first_seen: float
    last_seen: float
    
    tcp_flags: Optional[str] = None
    
    # Strictly metadata
    dns_metadata: Optional[Dict[str, Any]] = None
    tls_metadata: Optional[Dict[str, Any]] = None
    quic_metadata: Optional[Dict[str, Any]] = None
    
    service_label: Optional[str] = None
    raw_reference: Optional[Dict[str, Any]] = None
    schema_version: str = "1.0.0"
