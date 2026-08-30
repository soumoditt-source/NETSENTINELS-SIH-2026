"""Named safe scenarios exposed to the replay lab and benchmark runner."""

from collections.abc import Callable, Iterator
from typing import Any

from .safe_scenarios import (
    benign_cloud_sync,
    benign_messaging_periodic,
    benign_software_update,
    benign_web_browsing,
    c2_beaconing,
    dga_like_dns,
    dns_tunneling_like,
    exfiltration_like,
    horizontal_scan,
    mixed_enterprise_replay,
    suspicious_legit_service_c2,
    syn_flood,
    udp_flood,
    vertical_scan,
)

ScenarioFactory = Callable[..., Iterator[dict[str, Any]]]

SCENARIOS: dict[str, ScenarioFactory] = {
    "normal": benign_web_browsing,
    "web_browsing": benign_web_browsing,
    "software_update": benign_software_update,
    "cloud_sync": benign_cloud_sync,
    "messaging": benign_messaging_periodic,
    "syn_flood": syn_flood,
    "udp_flood": udp_flood,
    "horizontal_scan": horizontal_scan,
    "vertical_scan": vertical_scan,
    "beaconing": c2_beaconing,
    "dga": dga_like_dns,
    "dns_tunnel": dns_tunneling_like,
    "exfiltration": exfiltration_like,
    "legit_service_c2": suspicious_legit_service_c2,
    "mixed_enterprise": mixed_enterprise_replay,
}


def get_scenario(name: str) -> ScenarioFactory:
    """Return a known local scenario or raise a safe validation error."""

    try:
        return SCENARIOS[name]
    except KeyError as exc:
        raise ValueError(f"Unknown safe scenario: {name}") from exc


def scenario_names() -> tuple[str, ...]:
    """Return stable names for API validation and CLI help."""

    return tuple(sorted(SCENARIOS))
