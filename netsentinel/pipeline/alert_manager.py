"""Alert Manager — Creates structured alert JSON from model outputs.

Every alert follows a standardized schema with:
- Unique ID, timestamp, flow identifiers
- Threat classification + confidence
- MITRE ATT&CK mapping
- Severity assignment
- Metadata-only source and destination identities; no geolocation attribution
"""
import uuid
from datetime import datetime, timezone

from netsentinel.config import SEVERITY_MAP, MITRE_MAP, TARGET
from netsentinel.explanations.templates import build_explanation


class AlertManager:
    """Creates and stores alerts from model predictions."""
    
    def __init__(self, max_stored: int = 1000):
        self.alerts = []
        self.max_stored = max_stored
        self.total_count = 0
        self.threat_counts = {}
    
    def create_alert(
        self,
        model_result: dict,
        source_ip: str = None,
        dest_ip: str = None,
        flow_meta: dict = None,
    ) -> dict:
        """
        Create a structured alert from a model prediction.
        
        Args:
            model_result: dict from any model wrapper (has 'threat', 'confidence', etc.)
            source_ip: attacker IP (or random fake)
            dest_ip: target IP (default: our server)
            flow_meta: optional extra flow metadata
        
        Returns:
            Complete alert dict ready for WebSocket broadcast
        """
        threat = model_result.get("threat", "Unknown")
        confidence = model_result.get("confidence", 0.0)
        
        # Skip benign results
        if threat == "Benign":
            return None
        
        # Assign severity based on threat type + confidence
        base_severity = SEVERITY_MAP.get(threat, "MEDIUM")
        if confidence > 0.95:
            severity = "CRITICAL"
        elif confidence > 0.85:
            severity = base_severity
        elif confidence > 0.70:
            severity = "MEDIUM" if base_severity in ("CRITICAL", "HIGH") else "LOW"
        else:
            severity = "LOW"
        
        # Get MITRE mapping
        mitre = MITRE_MAP.get(threat, {"tactic": "Unknown", "technique": "T0000", "name": "Unknown"})
        
        source_ip = source_ip or "unknown"
        geo = {}
        
        alert = {
            "id":              str(uuid.uuid4()),
            "alert_id":        str(uuid.uuid4()),
            "schema_version":  "1.1.0",
            "timestamp":       datetime.now(timezone.utc).isoformat(),
            "source_ip":       source_ip,
            "dest_ip":         dest_ip or TARGET["ip"],
            "source_identity": source_ip,
            "destination_identity": dest_ip or TARGET["ip"],
            "threat_class":    threat,
            "threat_subtype":  model_result.get("subtype", model_result.get("class_name", "")),
            "confidence":      round(confidence, 4),
            "risk_score":      round(model_result.get("risk_score", confidence), 4),
            "status":           "open",
            "severity":        severity,
            "flow_id":         model_result.get("flow_id") or (flow_meta or {}).get("flow_id", ""),
            "related_flow_ids": model_result.get("related_flow_ids", []),
            "related_event_ids": model_result.get("related_event_ids", []),
            "detector":        model_result.get("model", "unknown"),
            "detector_method": model_result.get("method", "unknown"),
            "model_status":    model_result.get("model_status", "unknown"),
            "model_version":   model_result.get("model_version", "1.0.0"),
            "model_name":      model_result.get("model", "unknown"),
            "supporting_evidence": model_result.get("evidence", []),
            "feature_snapshot":    model_result.get("feature_snapshot", {}),
            "service_context":     model_result.get("service_context", {}),
            "mitre_attack_techniques": model_result.get("mitre", []),
            "mitre": mitre,
            "geo": geo,
            # SIH 26145 compliance assertions
            "read_only": True,
            "payload_decrypted": False,
            "limitations":     model_result.get("limitations", []),
            "possible_benign_explanations": model_result.get(
                "possible_benign_explanations",
                ["Approved automation, scheduled maintenance, or a legitimate transfer may look similar."],
            ),
            "false_positive_notes": model_result.get("false_positive_notes", []),
            "correlation_id": model_result.get("correlation_id"),
            "recommended_defensive_next_step": (
                model_result.get(
                    "recommended_defensive_next_step",
                    "Review metadata evidence and correlate with approved endpoint or change-management telemetry.",
                )
            ),
            "containment_scope": model_result.get("containment_scope", _containment_scope(threat)),
        }
        if flow_meta:
            alert["flow_meta"] = flow_meta
        alert["explanation"] = build_explanation(model_result, source_ip)
        
        # Store
        self.alerts.append(alert)
        if len(self.alerts) > self.max_stored:
            self.alerts = self.alerts[-self.max_stored:]
        
        self.total_count += 1
        self.threat_counts[threat] = self.threat_counts.get(threat, 0) + 1
        
        return alert
    
    def get_recent(self, n: int = 50) -> list:
        """Get the N most recent alerts."""
        return list(reversed(self.alerts[-n:]))
    
    def get_by_id(self, alert_id: str) -> dict | None:
        """Find an alert by its alert_id (UUID)."""
        for alert in reversed(self.alerts):
            if alert.get("alert_id") == alert_id or alert.get("id") == alert_id:
                return alert
        return None
    
    def get_stats(self) -> dict:
        """Get alert statistics for the dashboard."""
        return {
            "total_alerts": self.total_count,
            "threat_distribution": dict(self.threat_counts),
            "recent_count": len(self.alerts),
        }

    def reset(self):
        """Reset all counters and stored alerts."""
        self.alerts.clear()
        self.total_count = 0
        self.threat_counts.clear()


def _containment_scope(threat: str) -> dict[str, str | bool]:
    """Describe the smallest review boundary without performing enforcement."""
    scopes = {
        "DDoS": ("destination_service", "Review rate limiting for the affected destination service."),
        "Port Scan": ("source_identity", "Review or quarantine the scanning source/segment after authorization."),
        "DGA": ("source_dns_client", "Review the DNS client and queried domain family before changing DNS policy."),
        "DNS Tunnel": ("source_dns_client", "Review the DNS client and resolver path before restricting the domain family."),
        "C2 Beacon": ("source_to_destination_pair", "Correlate the source host and destination pair with endpoint telemetry."),
        "Suspicious Legitimate-Service Activity": ("source_to_service_pair", "Review the source host and service session chain; do not block the service globally."),
        "Data Exfiltration": ("source_to_destination_pair", "Review the source host and destination transfer, then apply approved egress controls."),
        "Encrypted Malware": ("source_to_destination_pair", "Correlate the encrypted session with endpoint and identity telemetry."),
    }
    scope, action = scopes.get(threat, ("flow_record", "Review this flow and corroborate with approved telemetry."))
    return {
        "scope_type": scope,
        "recommended_action": action,
        "automatic_enforcement": False,
        "read_only_reason": "NetSentinel never blocks traffic or sends commands across the ingest path.",
    }
