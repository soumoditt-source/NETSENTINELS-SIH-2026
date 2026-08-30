"""Write reproducible, offline-only replay bundles."""

from __future__ import annotations

import hashlib
import json
import csv
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

_FORBIDDEN_KEYS = {"payload", "raw_payload", "content", "credential", "token", "webhook"}


def _contains_forbidden_key(value: Any) -> bool:
    if isinstance(value, dict):
        return any(key.lower() in _FORBIDDEN_KEYS or _contains_forbidden_key(child) for key, child in value.items())
    if isinstance(value, list):
        return any(_contains_forbidden_key(child) for child in value)
    return False


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_replay_bundle(
    events: Iterable[dict[str, Any]],
    output_dir: str | Path,
    scenario: str,
    seed: int,
    write_parquet: bool = True,
) -> dict[str, Any]:
    """Write JSONL, CSV, and an optional tabular Parquet view."""

    destination = Path(output_dir).resolve()
    destination.mkdir(parents=True, exist_ok=True)
    materialized = list(events)
    if any(_contains_forbidden_key(event) for event in materialized):
        raise ValueError("safe replay records may not contain payloads, credentials, tokens, or webhooks")

    jsonl_path = destination / f"{scenario}_{seed}.jsonl"
    with jsonl_path.open("w", encoding="utf-8", newline="\n") as handle:
        for event in materialized:
            handle.write(json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n")

    outputs = [jsonl_path]

    csv_path = destination / f"{scenario}_{seed}.csv"
    csv_rows: list[dict[str, Any]] = []
    for event in materialized:
        row = {key: value for key, value in event.items() if key not in {"features", "_ground_truth"}}
        row["features_json"] = json.dumps(event.get("features", {}), sort_keys=True, separators=(",", ":"))
        row["ground_truth_json"] = json.dumps(event.get("_ground_truth", {}), sort_keys=True, separators=(",", ":"))
        csv_rows.append(row)
    fieldnames = sorted({key for row in csv_rows for key in row})
    with csv_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(csv_rows)
    outputs.append(csv_path)
    parquet_path: Path | None = None
    if write_parquet:
        import pandas as pd

        rows = []
        for event in materialized:
            row = {key: value for key, value in event.items() if key not in {"features", "_ground_truth"}}
            row["features_json"] = json.dumps(event.get("features", {}), sort_keys=True)
            row["ground_truth_json"] = json.dumps(event.get("_ground_truth", {}), sort_keys=True)
            rows.append(row)
        parquet_path = destination / f"{scenario}_{seed}.parquet"
        pd.DataFrame(rows).to_parquet(parquet_path, index=False, compression="zstd")
        outputs.append(parquet_path)

    manifest = {
        "scenario": scenario,
        "seed": seed,
        "is_synthetic": True,
        "offline_only": True,
        "is_executable": False,
        "payload_decrypted": False,
        "metadata_only": True,
        "supported_upload_formats": ["jsonl", "csv", "parquet"],
        "event_count": len(materialized),
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "outputs": {str(path): {"sha256": _sha256(path), "size_bytes": path.stat().st_size} for path in outputs},
    }
    manifest_path = destination / f"{scenario}_{seed}.manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return {"manifest": manifest, "manifest_path": str(manifest_path), "outputs": [str(path) for path in outputs]}
