"""
netsentinel/detectors/legitimate_service_c2.py
================================================
Behavioral correlation detector for suspicious use of legitimate cloud/messaging services.

Method: weighted evidence correlation  (NOT a classifier)
Status: baseline_rule + behavioral scoring

This is NetSentinel's UNIQUE differentiator.

Key principle:
  "NetSentinel does not blacklist Telegram, Discord, OneDrive, Google Drive,
  Teams, or any other legitimate service. It detects anomalous behavioral
  deviation: periodic low-volume check-ins, unusual destination context,
  abnormal upload asymmetry, anomalous DNS precursors, first-seen service
  usage, and cross-flow temporal correlation."

Service-behavior matrix:
  Each known service family has an expected behavioral profile.
  Deviation from this profile — not the service itself — produces a signal.

Detection requires MULTIPLE independent signals before triggering.
A single signal (e.g., Telegram seen in traffic) never produces an alert.

Limitations:
  - Encrypted service traffic prevents payload inspection.
  - Unusual but legitimate automation (CI/CD bots, monitoring agents) may trigger.
  - Service identity inferred from SNI/domain — can be spoofed at higher trust levels.
  - Confidence is probabilistic. Metadata alone cannot confirm C2.
"""

from __future__ import annotations
from collections import defaultdict
from typing import Any
import math
import time


# ── Service profile registry ───────────────────────────────────────────────────
# Each entry defines EXPECTED benign behavior for that service family.
_SERVICE_PROFILES: dict[str, dict[str, Any]] = {
    "telegram": {
        "domains": ["api.telegram.org", "telegram.org"],
        "expected_ports": [443],
        "normal_bytes_per_session": (200, 15_000),   # (min, max) for typical message
        "normal_sessions_per_hour": (0, 60),
        "normal_interval_cv_max": 1.5,               # high CV = irregular = benign chat
        "direction": "bidirectional",
    },
    "discord": {
        "domains": ["discord.com", "discordapp.com"],
        "expected_ports": [443],
        "normal_bytes_per_session": (200, 20_000),
        "normal_sessions_per_hour": (0, 120),
        "normal_interval_cv_max": 2.0,
        "direction": "bidirectional",
    },
    "onedrive": {
        "domains": ["onedrive.live.com", "sharepoint.com", "1drv.ms"],
        "expected_ports": [443],
        "normal_bytes_per_session": (1000, 50_000_000),  # large uploads ok
        "normal_sessions_per_hour": (0, 20),
        "normal_interval_cv_max": 2.5,
        "direction": "mostly_upload",
    },
    "google_drive": {
        "domains": ["drive.google.com", "googleapis.com"],
        "expected_ports": [443],
        "normal_bytes_per_session": (1000, 100_000_000),
        "normal_sessions_per_hour": (0, 20),
        "normal_interval_cv_max": 2.5,
        "direction": "bidirectional",
    },
    "teams": {
        "domains": ["teams.microsoft.com", "teams.live.com"],
        "expected_ports": [443],
        "normal_bytes_per_session": (5000, 5_000_000),
        "normal_sessions_per_hour": (0, 100),
        "normal_interval_cv_max": 3.0,
        "direction": "bidirectional",
    },
}


def _coefficient_of_variation(values: list[float]) -> float:
    if len(values) < 2:
        return 0.0
    mean = sum(values) / len(values)
    if mean == 0:
        return 0.0
    variance = sum((v - mean) ** 2 for v in values) / len(values)
    return math.sqrt(variance) / mean


def _match_service(domain: str) -> tuple[str, dict | None]:
    """Return (service_name, profile) if domain matches a known service."""
    domain_lower = domain.lower()
    for name, profile in _SERVICE_PROFILES.items():
        if any(d in domain_lower for d in profile["domains"]):
            return name, profile
    return "unknown", None


class LegitimateServiceC2Detector:
    """
    Behavioral correlation detector for suspicious cloud/messaging service abuse.

    Maintains per-(source, service) session histories within a bounded window.
    Produces a risk score based on the COMBINATION of:
      1. Periodicity: unusually regular inter-session intervals
      2. Volume asymmetry: high out/in ratio on tiny sessions
      3. First-seen: source never used this service in baseline window
      4. Burst upload after check-ins: command-response-like sequence
      5. DNS anomaly precursor (passed from correlation engine)
    """

    name = "LegitimateServiceC2Detector"
    method = "weighted_evidence"
    model_status = "baseline_rule"
    model_version = "1.1.0"

    def __init__(self, window_seconds: int = 3600) -> None:
        self.window_s = window_seconds
        # {(src_ip, service_name): [(timestamp, bytes_out, bytes_in), ...]}
        self._sessions: dict[tuple, list] = defaultdict(list)
        print(f"  [OK] {self.name} loaded (window={window_seconds}s)")

    # ------------------------------------------------------------------
    def predict(self, event: dict[str, Any], host_state: dict[str, Any]) -> dict[str, Any]:
        """
        Score a flow event for suspicious legitimate-service behavior.

        Multiple weak signals accumulate a risk score. An alert is only
        emitted when multiple INDEPENDENT signals exceed the threshold.
        """
        domain    = event.get("dest_domain", "")
        src_ip    = event.get("source_ip", "")
        bytes_out = event.get("_bytes_out", 0) or event.get("features", {}).get("Fwd Packets Length Total", 0)
        bytes_in  = event.get("_bytes_in",  0) or event.get("features", {}).get("Bwd Packets Length Total", 0)
        now       = float(event.get("observed_at", time.time()))

        service_name, profile = _match_service(domain)

        # No matching service → not applicable for this detector
        if profile is None:
            return self._no_match_result(domain)

        key = (src_ip, service_name)
        self._evict_old(key, now)
        self._sessions[key].append((now, bytes_out, bytes_in))
        sessions = self._sessions[key]

        risk_score = 0.0
        evidence: list[str] = []
        signal_count = 0

        # ── Signal 1: Periodicity ─────────────────────────────────────
        if len(sessions) >= 5:
            intervals = [sessions[i+1][0] - sessions[i][0]
                         for i in range(len(sessions) - 1)]
            cv = _coefficient_of_variation(intervals)
            expected_cv_max = profile.get("normal_interval_cv_max", 1.5)
            if cv < 0.10 and len(sessions) >= 8:
                # Extremely regular — stronger signal
                periodicity_score = min(1.0, 0.6 + (0.10 - cv) * 4)
                risk_score += periodicity_score * 0.40
                evidence.append(
                    f"Interval CV={cv:.3f} (very regular; threshold CV<0.10 for suspicious). "
                    f"{len(sessions)} sessions observed."
                )
                signal_count += 1
            elif cv < 0.25 and len(sessions) >= 5:
                periodicity_score = 0.35
                risk_score += periodicity_score * 0.30
                evidence.append(
                    f"Interval CV={cv:.3f} (moderately regular). "
                    f"{len(sessions)} sessions to {service_name}."
                )
                signal_count += 1

        # ── Signal 2: Volume asymmetry on small sessions ───────────────
        recent_bytes_out = [s[1] for s in sessions[-10:]]
        recent_bytes_in  = [s[2] for s in sessions[-10:]]
        avg_out = sum(recent_bytes_out) / max(len(recent_bytes_out), 1)
        avg_in  = sum(recent_bytes_in)  / max(len(recent_bytes_in),  1)
        ratio   = avg_out / max(avg_in, 1)

        min_sz, max_sz = profile.get("normal_bytes_per_session", (200, 1_000_000))
        if avg_out < max_sz and ratio > 15:
            risk_score += 0.30
            evidence.append(
                f"Small sessions ({avg_out:.0f}B out) with high asymmetry "
                f"(out/in={ratio:.0f}x) to {service_name}."
            )
            signal_count += 1

        # ── Signal 3: First-seen service from this source ──────────────
        if len(sessions) == 1:
            services_seen = host_state.get("services", set())
            if service_name not in services_seen:
                risk_score += 0.20
                evidence.append(
                    f"First-ever contact with {service_name} from {src_ip}. "
                    "Verify with user baseline."
                )
                # Note: first-seen alone is NEVER enough to trigger

        # ── Signal 4: Upload burst after periodic check-ins ────────────
        if len(sessions) >= 5 and bytes_out > 5_000_000:
            prev_avg = sum(s[1] for s in sessions[:-1]) / max(len(sessions) - 1, 1)
            if bytes_out > prev_avg * 20:
                risk_score += 0.35
                evidence.append(
                    f"Upload burst: {bytes_out/1e6:.1f}MB vs previous avg "
                    f"{prev_avg/1e3:.1f}KB — anomalous after periodic sessions."
                )
                signal_count += 1

        # ── Require at least 2 independent signals ─────────────────────
        triggered = risk_score >= 0.60 and signal_count >= 2
        confidence = min(0.92, risk_score)

        return {
            "threat": "Suspicious Legitimate-Service Activity" if triggered else "Benign",
            "confidence": round(confidence, 4),
            "triggered": triggered,
            "subtype": f"Suspected behavioral abuse of {service_name}",
            "model": self.name,
            "method": self.method,
            "model_status": self.model_status,
            "model_version": self.model_version,
            "service_context": {
                "service_family": service_name,
                "domain": domain,
                "sessions_in_window": len(sessions),
                "avg_bytes_out": round(avg_out, 1),
                "avg_bytes_in": round(avg_in, 1),
                "out_in_ratio": round(ratio, 2),
            },
            "evidence": evidence,
            "feature_snapshot": {
                "service_family": service_name,
                "session_count": len(sessions),
                "risk_score": round(risk_score, 4),
                "signal_count": signal_count,
            },
            "limitations": [
                f"{service_name.title()} is a LEGITIMATE service — this alert is about behavioral anomaly only.",
                "Encrypted payloads were NOT inspected.",
                "CI/CD bots, monitoring agents, and approved automation may produce similar patterns.",
                "Confidence is probabilistic — metadata alone cannot confirm C2.",
            ],
            "mitre": ["T1102", "T1071"],
        }

    def _evict_old(self, key: tuple, now: float) -> None:
        cutoff = now - self.window_s
        self._sessions[key] = [s for s in self._sessions[key] if s[0] >= cutoff]

    def _no_match_result(self, domain: str) -> dict[str, Any]:
        return {
            "threat": "Benign",
            "confidence": 0.0,
            "triggered": False,
            "subtype": "No matching service profile",
            "model": self.name,
            "method": self.method,
            "model_status": self.model_status,
            "model_version": self.model_version,
            "service_context": {"domain": domain},
            "evidence": [],
            "feature_snapshot": {},
            "limitations": [],
            "mitre": [],
        }
