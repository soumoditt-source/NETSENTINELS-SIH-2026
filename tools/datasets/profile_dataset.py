"""Profile a local CSV without downloading or executing it."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import pandas as pd


def main() -> int:
    """Write a compact schema and null profile."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("csv_path")
    parser.add_argument("--sample", type=int, default=10000)
    parser.add_argument("--output", default="data/reports/profiling/dataset_profile.json")
    args = parser.parse_args()
    path = Path(args.csv_path).resolve()
    frame = pd.read_csv(path, nrows=args.sample, low_memory=False)
    result = {
        "path": str(path),
        "sample_rows": len(frame),
        "columns": {column: str(dtype) for column, dtype in frame.dtypes.items()},
        "missing_values": {column: int(value) for column, value in frame.isna().sum().items()},
    }
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
