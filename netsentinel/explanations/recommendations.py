"""Human-review recommendations for metadata alerts."""


def recommendation_for(threat: str, source: str) -> str:
    """Return a verification action; never issue a blocking or network command."""

    normalized = threat.lower()
    if "scan" in normalized:
        return f"Check whether {source} is an approved scanner and compare the event with the maintenance calendar."
    if "exfil" in normalized or "transfer" in normalized:
        return f"Verify whether {source} has an approved backup or transfer job, then review endpoint telemetry if available."
    if "dns" in normalized:
        return f"Review the requesting application and DNS resolver context for {source}; do not infer intent from the name alone."
    if "service" in normalized or "beacon" in normalized:
        return f"Confirm whether {source} is approved to use this service and inspect scheduled tasks or agent configuration."
    return f"Correlate the metadata for {source} with approved endpoint, identity, and change-management telemetry."
