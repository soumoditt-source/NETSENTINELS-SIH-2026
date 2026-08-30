"""Possible benign explanations for common metadata observations."""

from typing import Any


def alternatives_for(threat: str, service: str | None = None) -> list[str]:
    """Return cautious alternatives without converting them into exclusions."""

    normalized = threat.lower()
    if "scan" in normalized or "recon" in normalized:
        return ["An approved vulnerability assessment or maintenance scan may look similar."]
    if "exfil" in normalized or "transfer" in normalized:
        return ["An approved backup, cloud sync, or data-migration job may explain the upload."]
    if "service" in normalized or "beacon" in normalized:
        return ["A monitoring agent, software update, or scheduled automation may explain the recurrence."]
    if "dns" in normalized:
        return ["A vendor-generated hostname or a newly deployed application may explain the DNS pattern."]
    if "encrypt" in normalized:
        return ["A legitimate application or new TLS client can produce an unfamiliar metadata fingerprint."]
    return [f"Approved automation or a newly deployed application may explain this {service or 'network'} pattern."]
