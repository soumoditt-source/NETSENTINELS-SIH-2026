"""Generate explicitly requested offline replay bundles."""

from __future__ import annotations

import argparse
import json

from netsentinel.simulator.safe_trace_writer import write_replay_bundle
from netsentinel.simulator.scenario_catalog import get_scenario, scenario_names


def main() -> int:
    """Generate one known scenario without any network operation."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scenario", default="mixed_enterprise", choices=scenario_names())
    parser.add_argument("--output-dir", default="data/processed/safe_lab")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--events", type=int, default=200)
    args = parser.parse_args()
    if args.events <= 0:
        raise SystemExit("--events must be positive")
    factory = get_scenario(args.scenario)
    if args.scenario == "mixed_enterprise":
        events = factory(seed=args.seed, n_total=args.events)
    else:
        events = factory(seed=args.seed)
    result = write_replay_bundle(events, args.output_dir, args.scenario, args.seed)
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
