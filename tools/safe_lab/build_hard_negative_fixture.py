"""Build a metadata-only hard-negative fixture for safe detector testing.

This fixture contains no executable, payload, credential, evasion content, or
real C2. It combines benign cloud/messaging behavior with a synthetic
legitimate-service behavioral anomaly so analysts can test false-positive
handling and evidence presentation safely.
"""

from __future__ import annotations

import argparse
import json
from itertools import chain

from netsentinel.simulator.safe_scenarios import (
    benign_cloud_sync,
    benign_messaging_periodic,
    suspicious_legit_service_c2,
)
from netsentinel.simulator.safe_trace_writer import write_replay_bundle


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", default="data/processed/safe_lab")
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()
    events = chain(
        benign_cloud_sync(seed=args.seed, n=12),
        benign_messaging_periodic(seed=args.seed + 1, n=20),
        suspicious_legit_service_c2(seed=args.seed + 2, n_checkins=18),
    )
    result = write_replay_bundle(events, args.output_dir, "hard_negative_legitimate_service", args.seed)
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
