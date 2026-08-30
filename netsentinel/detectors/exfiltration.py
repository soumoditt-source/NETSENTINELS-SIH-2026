"""
netsentinel/detectors/exfiltration.py
=======================================
Baseline detector for data exfiltration via asymmetric byte-volume analysis.

Method: rule-based  (NOT a trained ML model)
Status: baseline_rule

Key design decisions:
  - A large upload alone does NOT trigger an alert.
    Known cloud-service domains and high-bandwidth sessions are context-aware.
  - The detector requires BOTH high absolute outbound volume AND
    a high outbound/inbound ratio to flag as suspicious.
  - An explicit distinction is made between:
      "Large Transfer" (informational) and
      "Suspicious Exfiltration-like Behavior" (actionable alert).

Limitations:
  - Legitimate cloud backups (e.g., OneDrive, Dropbox) may trigger if the
    inbound response is very small (e.g., 200 OK with no body).
  - Encrypted channels prevent payload inspection.
  - This is NOT a trained model. It is a deterministic baseline.
"""

from __future__ import annotations
from typing import Any


# ── Configurable thresholds ────────────────────────────────────────────────────
_MIN_BYTES_OUT       = 5_000_000    # 5 MB minimum to even consider flagging
_HIGH_BYTES_OUT      = 20_000_000   # 20 MB → "large transfer" informational
_CRITICAL_BYTES_OUT  = 100_000_000  # 100 MB → higher-confidence
_SUSPICIOUS_RATIO    = 20.0         # out/in > 20 → suspicious
_CRITICAL_RATIO      = 100.0        # out/in > 100 → very suspicious


class ExfiltrationBaselineDetector:
    """
    Deterministic asymmetric byte-volume baseline for data exfiltration detection.

    Uses host_state supplied by StateManager — specifically the cumulative
    bytes_out and bytes_in within the current TTL window.
    """

    name = "ExfiltrationBaselineDetector"
    method = "rule"
    model_status = "baseline_rule"
    model_version = "1.1.0"

    def __init__(
        self,
        min_bytes_out: int   = _MIN_BYTES_OUT,
        suspicious_ratio: float = _SUSPICIOUS_RATIO,
    ) -> None:
        self.min_bytes_out    = min_bytes_out
        self.suspicious_ratio = suspicious_ratio
        print(f"  [OK] {self.name} loaded "
              f"(min_bytes_out={min_bytes_out/1e6:.0f}MB, ratio>{suspicious_ratio:.0f}x)")

    # ------------------------------------------------------------------
    def predict(self, event: dict[str, Any], host_state: dict[str, Any]) -> dict[str, Any]:
        """
        Evaluate exfiltration risk for a source host.

        Args:
            event:      Normalized event dict; may carry ``_bytes_out`` / ``_bytes_in``
                        directly injected by the scenario generator.
            host_state: Per-source state from StateManager.

        Returns:
            Standard detector result dict.
        """
        # Prefer state-window totals; fall back to event-level injection
        bytes_out = host_state.get("bytes_out", 0)
        bytes_in  = host_state.get("bytes_in",  0)

        # For simulator events that inject per-event values
        bytes_out = max(bytes_out, event.get("_bytes_out", 0))
        bytes_in  = max(bytes_in,  event.get("_bytes_in",  0))

        # Also check flow features (Total Fwd ≈ outbound for client-initiated)
        features   = event.get("features", {})
        fwd_bytes  = features.get("Fwd Packets Length Total", 0)
        bwd_bytes  = features.get("Bwd Packets Length Total", 0)
        if fwd_bytes > bytes_out:
            bytes_out = fwd_bytes
        if bwd_bytes > bytes_in:
            bytes_in  = bwd_bytes

        dest_domain   = event.get("dest_domain", "")
        ratio         = bytes_out / max(bytes_in, 1)
        triggered     = False
        subtype       = "benign"
        confidence    = 0.0
        evidence: list[str] = []

        # ── Volume + ratio logic ──────────────────────────────────────
        if bytes_out >= self.min_bytes_out:
            if ratio >= _CRITICAL_RATIO:
                triggered  = True
                subtype    = "High-Volume High-Ratio Suspicious Transfer"
                confidence = min(0.97, 0.85 + (ratio / 1000))
                evidence.append(f"Bytes out: {bytes_out/1e6:.1f} MB")
                evidence.append(f"Bytes in: {bytes_in:,} bytes")
                evidence.append(f"Out/in ratio: {ratio:.0f}x (threshold: {_CRITICAL_RATIO:.0f}x)")

            elif ratio >= self.suspicious_ratio:
                triggered  = True
                subtype    = "Suspicious Outbound Volume Asymmetry"
                confidence = min(0.92, 0.68 + (ratio / 200))
                evidence.append(f"Bytes out: {bytes_out/1e6:.1f} MB")
                evidence.append(f"Bytes in: {bytes_in:,} bytes")
                evidence.append(f"Out/in ratio: {ratio:.1f}x (threshold: {self.suspicious_ratio:.0f}x)")

            elif bytes_out >= _HIGH_BYTES_OUT:
                # Large transfer but ratio is not suspicious — informational only
                subtype    = "Large Transfer (Informational)"
                confidence = 0.25   # Low — do not alert
                evidence.append(
                    f"Large upload {bytes_out/1e6:.0f} MB but ratio {ratio:.1f}x is within normal range"
                )
                if dest_domain:
                    evidence.append(f"Destination service: {dest_domain}")

        # Context: known cloud service lowers confidence slightly
        known_cloud = any(svc in dest_domain for svc in [
            "onedrive", "google", "dropbox", "box.com", "icloud",
            "sharepoint", "teams", "gdrive",
        ])
        if triggered and known_cloud:
            confidence *= 0.80
            evidence.append(
                f"Destination is a known cloud service ({dest_domain}) — confidence reduced."
                " Verify against approved backup policy."
            )

        return {
            "threat": "Data Exfiltration" if triggered else subtype or "Benign",
            "confidence": round(confidence, 4),
            "triggered": triggered,
            "subtype": subtype,
            "model": self.name,
            "method": self.method,
            "model_status": self.model_status,
            "model_version": self.model_version,
            "evidence": evidence,
            "feature_snapshot": {
                "bytes_out":      bytes_out,
                "bytes_in":       bytes_in,
                "out_in_ratio":   round(ratio, 2),
                "dest_domain":    dest_domain,
                "known_cloud_svc": known_cloud,
            },
            "limitations": [
                "Legitimate cloud backups with small HTTP responses may trigger.",
                "Encrypted channels prevent payload inspection.",
                "Does not distinguish archive creation from live exfiltration.",
                "No trained ML model — threshold-based heuristic baseline only.",
            ],
            "mitre": ["T1041", "T1048"],
        }
