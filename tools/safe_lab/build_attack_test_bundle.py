"""Build a deterministic, metadata-only attack-signature test bundle.

The bundle models observable flow and DNS patterns for defensive validation.
It contains no packets, payloads, exploit code, credentials, malware, or
network callbacks. The records are safe to upload to NetSentinel's replay API.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from itertools import chain
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from netsentinel.simulator.safe_scenarios import (
    benign_cloud_sync,
    benign_messaging_periodic,
    benign_software_update,
    benign_web_browsing,
    c2_beaconing,
    dga_like_dns,
    dns_tunneling_like,
    exfiltration_like,
    horizontal_scan,
    suspicious_legit_service_c2,
    slow_stealth_scan,
    syn_flood,
    udp_flood,
    vertical_scan,
)
from netsentinel.simulator.safe_trace_writer import write_replay_bundle


def _build_events(seed: int) -> list[dict]:
    cases = [
        benign_web_browsing(seed=seed, n=16),
        benign_software_update(seed=seed + 1, n=4),
        benign_cloud_sync(seed=seed + 2, n=6),
        benign_messaging_periodic(seed=seed + 3, n=15),
        syn_flood(seed=seed + 10, n=120),
        udp_flood(seed=seed + 11, n=100),
        horizontal_scan(seed=seed + 14, n_targets=40),
        vertical_scan(seed=seed + 15, n_ports=40),
        slow_stealth_scan(seed=seed + 16, n=25),
        c2_beaconing(seed=seed + 17, n=25),
        dga_like_dns(seed=seed + 18, n=20),
        dns_tunneling_like(seed=seed + 19, n=16),
        exfiltration_like(seed=seed + 21, n=4),
        suspicious_legit_service_c2(seed=seed + 23, n_checkins=16),
    ]
    return list(chain.from_iterable(cases))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", default="data/processed/safe_lab")
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    events = _build_events(args.seed)
    bundle_dir = Path(args.output_dir) / f"netsentinel_attack_test_bundle_{args.seed}"
    result = write_replay_bundle(events, bundle_dir, "attack_signatures", args.seed)
    manifest_path = Path(result["manifest_path"])
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["outputs"] = {
        Path(path).name: metadata
        for path, metadata in manifest.get("outputs", {}).items()
    }
    scenarios = Counter(event.get("_ground_truth", {}).get("scenario", "unknown") for event in events)
    manifest.update({
        "fixture_purpose": "Defensive metadata-only detector and temporal-forensics validation",
        "test_cases": [
            "benign_web_browsing",
            "software_update_hard_negative",
            "cloud_sync_hard_negative",
            "normal_messaging_hard_negative",
            "syn_flood_like",
            "udp_flood_like",
            "horizontal_port_scan_like",
            "vertical_port_scan_like",
            "low_and_slow_scan_like",
            "periodic_beacon_like",
            "dga_dns_like",
            "dns_tunneling_like",
            "asymmetric_exfiltration_like",
            "legitimate_service_c2_chain_like",
        ],
        "scenario_counts": dict(sorted(scenarios.items())),
        "safety": {
            "offline_only": True,
            "is_executable": False,
            "contains_payload": False,
            "contains_credentials": False,
            "uses_documentation_networks": True,
            "requires_authorized_lab_only": True,
        },
    })
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    readme = bundle_dir / "README.md"
    readme.write_text(
        "# NetSentinel safe metadata test bundle\n\n"
        "This bundle contains synthetic flow/DNS metadata only. It is not a "
        "malware sample, exploit, packet capture, or executable file. It is "
        "designed to exercise NetSentinel's read-only detector and temporal "
        "forensics paths offline.\n\n"
        "## Test in the dashboard\n\n"
        "1. Start NetSentinel on ports 8100 and 5174.\n"
        "2. Open `http://localhost:5174` and click **Launch analysis**.\n"
        "3. Switch to **Explain**, choose `attack_signatures_42.jsonl`, "
        "`.csv`, or `.parquet`, and inspect the alert evidence.\n\n"
        "## Test with the API\n\n"
        "```bash\n"
        "curl -X POST http://localhost:8100/api/forensics/upload "
        "-F 'file=@attack_signatures_42.jsonl'\n"
        "curl http://localhost:8100/api/forensics/temporal\n"
        "```\n\n"
        "All records use documentation-only addresses and carry explicit "
        "ground truth in `_ground_truth`.\n",
        encoding="utf-8",
    )
    result["bundle_dir"] = str(bundle_dir.resolve())
    result["manifest"] = manifest
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
