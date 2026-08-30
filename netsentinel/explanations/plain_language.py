"""Plain-language alert summaries for non-technical viewers."""

from typing import Any

from .benign_alternatives import alternatives_for
from .evidence_formatter import format_evidence
from .recommendations import recommendation_for


def build_plain_explanation(result: dict[str, Any], source: str = "this device") -> dict[str, Any]:
    """Transform detector output into a cautious, reviewable explanation."""

    threat = str(result.get("threat", result.get("threat_class", "network behavior")))
    evidence = list(result.get("evidence", []))
    first_evidence = evidence[0] if evidence else "a metadata pattern differed from the configured baseline"
    return {
        "title": f"Possible {threat.lower()} behavior from {source}",
        "plain_language": (
            f"{source} showed {first_evidence.lower()}. This can be unusual in context, "
            "but metadata evidence alone does not prove malicious activity."
        ),
        "why_flagged": evidence,
        "possible_benign_explanations": alternatives_for(threat, result.get("service_context", {}).get("service_family")),
        "recommended_analyst_check": recommendation_for(threat, source),
        "technical_evidence": format_evidence(result),
        "limitations": result.get("limitations", []),
        "safety": "Read-only monitoring; encrypted payloads were not decrypted and no traffic was sent back.",
    }
