"""Reproducible CIC-IDS2017 CSV factory.

The factory is intentionally local-first. It never downloads data, executes a
file, or contacts the observed network. A separate downloader requires an
explicit command and records provenance before preparation begins.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

import pandas as pd

SCHEMA_VERSION = "1.0.0"
SPLIT_VERSION = "1.0.0"
SOURCE_URL = "https://www.unb.ca/cic/datasets/ids-2017.html"
DATASET_NAME = "CIC-IDS2017"

LABEL_COLUMN_CANDIDATES = ("label", "class", "attack", "target")
TIMESTAMP_COLUMN_CANDIDATES = ("timestamp", "time", "date")
IDENTITY_COLUMN_CANDIDATES = {
    "flow_id": ("flow id", "flow_id", "uid"),
    "source_ip": ("source ip", "src ip", "id.orig_h"),
    "destination_ip": ("destination ip", "dest ip", "id.resp_h"),
}
DROP_COLUMN_NAMES = {"unnamed: 0", "index", "row number"}
KNOWN_COLUMN_NAMES = {
    "total length of fwd packets": "fwd packets length total",
    "total length of bwd packets": "bwd packets length total",
    "flow packets/s": "flow packets/s",
    "flow bytes/s": "flow bytes/s",
    "destination port": "destination port",
    "flow duration": "flow duration",
    "label": "label",
}
LABEL_MAP = {
    "benign": "benign",
    "ddos": "ddos",
    "dos hulk": "ddos",
    "dos goldeneye": "ddos",
    "dos slowloris": "ddos",
    "dos slowhttptest": "ddos",
    "portscan": "reconnaissance",
    "bot": "botnet_or_c2_like",
    "infiltration": "exfiltration_like",
    "heartbleed": "other_attack",
    "ftp-patator": "other_attack",
    "ssh-patator": "other_attack",
    "web attack - brute force": "other_attack",
    "web attack - xss": "other_attack",
    "web attack - sql injection": "other_attack",
}


def utc_now() -> str:
    """Return an explicit UTC timestamp for provenance records."""

    return datetime.now(timezone.utc).isoformat()


def normalize_column_name(value: str) -> str:
    """Normalize a source column without losing its original spelling."""

    cleaned = re.sub(r"\s+", " ", str(value).strip()).lower()
    return KNOWN_COLUMN_NAMES.get(cleaned, cleaned)


def discover_csv_files(input_dir: Path, csv_glob: str = "**/*.csv") -> list[Path]:
    """Discover CSV files deterministically and reject directories as inputs."""

    if not input_dir.is_dir():
        raise FileNotFoundError(f"CIC input directory does not exist: {input_dir}")
    files = sorted(path for path in input_dir.glob(csv_glob) if path.is_file())
    if not files:
        raise FileNotFoundError(f"No CSV files found below {input_dir}")
    return files


def _find_column(columns: Iterable[str], candidates: Iterable[str]) -> str | None:
    normalized = {normalize_column_name(column): column for column in columns}
    for candidate in candidates:
        found = normalized.get(normalize_column_name(candidate))
        if found:
            return found
    return None


def canonicalize_label(value: Any) -> tuple[str, float]:
    """Map only explicitly known CIC labels; unknown labels remain unknown."""

    original = str(value).strip().lower()
    if original in LABEL_MAP:
        return LABEL_MAP[original], 1.0
    return "unknown", 0.0


def _capture_id(path: Path) -> str:
    stem = re.sub(r"[^a-z0-9]+", "_", path.stem.lower()).strip("_")
    return stem or "unknown_capture"


def _stable_identity(value: Any, salt: str) -> str:
    digest = hashlib.sha256(f"{salt}:{value}".encode("utf-8")).hexdigest()
    return f"anon_{digest[:16]}"


def _stable_flow_id(value: Any, path: Path, row_number: int, salt: str) -> str:
    raw = f"{salt}:{path.name}:{row_number}:{value}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:24]


def _read_source(path: Path, sample_rows: int | None, seed: int) -> pd.DataFrame:
    frame = pd.read_csv(
        path,
        low_memory=False,
        on_bad_lines="error",
    )
    raw_rows = len(frame)
    if sample_rows is not None and raw_rows > sample_rows:
        label_column = _find_column(frame.columns, LABEL_COLUMN_CANDIDATES)
        if label_column:
            selected_parts: list[pd.DataFrame] = []
            groups = list(frame.groupby(label_column, dropna=False, sort=True))
            quota = max(1, sample_rows // max(len(groups), 1))
            for _, group in groups:
                selected_parts.append(group.sample(n=min(len(group), quota), random_state=seed))
            selected = pd.concat(selected_parts, axis=0) if selected_parts else frame.iloc[0:0]
            remaining = sample_rows - len(selected)
            if remaining > 0:
                remainder = frame.drop(index=selected.index)
                if len(remainder):
                    selected = pd.concat([
                        selected,
                        remainder.sample(n=min(remaining, len(remainder)), random_state=seed + 1),
                    ])
            frame = selected.sort_index(kind="stable").reset_index(drop=True)
        else:
            frame = frame.sample(n=sample_rows, random_state=seed).sort_index(kind="stable").reset_index(drop=True)
    frame.attrs["raw_source_rows"] = raw_rows
    return frame


def _clean_frame(path: Path, frame: pd.DataFrame, salt: str) -> tuple[pd.DataFrame, dict[str, Any]]:
    original_columns = [str(column) for column in frame.columns]
    renamed = {column: normalize_column_name(column) for column in frame.columns}
    frame = frame.rename(columns=renamed)
    duplicate_columns = frame.columns[frame.columns.duplicated()].tolist()
    if duplicate_columns:
        frame = frame.loc[:, ~frame.columns.duplicated()]

    label_column = _find_column(frame.columns, LABEL_COLUMN_CANDIDATES)
    if label_column is None:
        raise ValueError(f"Could not identify a label column in {path.name}")
    timestamp_column = _find_column(frame.columns, TIMESTAMP_COLUMN_CANDIDATES)
    flow_column = _find_column(frame.columns, IDENTITY_COLUMN_CANDIDATES["flow_id"])
    source_column = _find_column(frame.columns, IDENTITY_COLUMN_CANDIDATES["source_ip"])
    destination_column = _find_column(frame.columns, IDENTITY_COLUMN_CANDIDATES["destination_ip"])

    quality: dict[str, Any] = {
        "source_file": str(path),
        "source_rows": int(frame.attrs.get("raw_source_rows", len(frame))),
        "original_columns": original_columns,
        "normalized_columns": list(frame.columns),
        "duplicate_columns_removed": duplicate_columns,
        "infinity_replacements": 0,
        "numeric_coercions_to_null": 0,
        "nulls_filled": 0,
        "duplicate_rows_removed": 0,
    }

    original_labels = frame[label_column].fillna("<missing>").astype(str).str.strip()
    mapped = original_labels.map(canonicalize_label)
    frame["original_label"] = original_labels
    frame["canonical_label"] = mapped.map(lambda item: item[0])
    frame["label_confidence"] = mapped.map(lambda item: item[1])
    frame["dataset_source"] = DATASET_NAME
    frame["capture_id"] = _capture_id(path)
    frame["source_file"] = path.name
    frame["is_synthetic"] = False

    if flow_column:
        frame["flow_id"] = [
            _stable_flow_id(value, path, index, salt)
            for index, value in enumerate(frame[flow_column].tolist())
        ]
    else:
        frame["flow_id"] = [
            _stable_flow_id("missing", path, index, salt)
            for index in range(len(frame))
        ]
    frame["source_identity"] = frame[source_column].map(lambda value: _stable_identity(value, salt)) if source_column else "anon_unknown"
    frame["destination_identity"] = frame[destination_column].map(lambda value: _stable_identity(value, salt)) if destination_column else "anon_unknown"

    if timestamp_column:
        parsed = pd.to_datetime(frame[timestamp_column], errors="coerce", utc=True)
        frame["observed_at"] = parsed
    else:
        frame["observed_at"] = pd.NaT

    protected = {
        label_column,
        timestamp_column,
        flow_column,
        source_column,
        destination_column,
        "original_label",
        "canonical_label",
        "label_confidence",
        "dataset_source",
        "capture_id",
        "source_file",
        "is_synthetic",
        "flow_id",
        "source_identity",
        "destination_identity",
        "observed_at",
    }
    protected.discard(None)
    for column in list(frame.columns):
        if column in protected:
            continue
        if normalize_column_name(column) in DROP_COLUMN_NAMES:
            frame = frame.drop(columns=column)
            continue
        before_non_null = frame[column].notna().sum()
        numeric = pd.to_numeric(frame[column], errors="coerce")
        quality["numeric_coercions_to_null"] += int(before_non_null - numeric.notna().sum())
        numeric = numeric.replace([math.inf, -math.inf], pd.NA)
        quality["infinity_replacements"] += int(frame[column].isin([math.inf, -math.inf]).sum())
        if numeric.notna().any():
            fill_value = float(numeric.median()) if pd.notna(numeric.median()) else 0.0
            quality["nulls_filled"] += int(numeric.isna().sum())
            frame[column] = numeric.fillna(fill_value).astype("float64")

    before = len(frame)
    frame = frame.drop_duplicates(keep="first").reset_index(drop=True)
    quality["duplicate_rows_removed"] = before - len(frame)
    quality["output_rows"] = int(len(frame))
    return frame, quality


def _split_frame(frame: pd.DataFrame, seed: int) -> tuple[dict[str, pd.DataFrame], dict[str, Any]]:
    """Split by capture where possible, with a documented temporal fallback."""

    captures = sorted(frame["capture_id"].dropna().unique().tolist())
    if len(captures) >= 3:
        hashed = sorted(captures, key=lambda value: hashlib.sha256(f"{seed}:{value}".encode()).hexdigest())
        pure_benign = [
            capture for capture in hashed
            if (frame.loc[frame["capture_id"] == capture, "canonical_label"] == "benign").all()
        ]
        mixed_or_attack = [capture for capture in hashed if capture not in pure_benign]
        ordered = pure_benign + mixed_or_attack
        cut_train = max(1, int(len(ordered) * 0.60))
        cut_validation = max(cut_train + 1, int(len(ordered) * 0.80))
        groups = {
            "train": ordered[:cut_train],
            "validation": ordered[cut_train:cut_validation],
            "test": ordered[cut_validation:],
        }
        splits = {name: frame[frame["capture_id"].isin(values)].copy() for name, values in groups.items()}
        method = "capture_grouped_hash_split"
    elif frame["observed_at"].notna().sum() >= 3:
        ordered_frame = frame.sort_values("observed_at", kind="stable").reset_index(drop=True)
        cut_train = max(1, int(len(ordered_frame) * 0.60))
        cut_validation = max(cut_train + 1, int(len(ordered_frame) * 0.80))
        splits = {
            "train": ordered_frame.iloc[:cut_train].copy(),
            "validation": ordered_frame.iloc[cut_train:cut_validation].copy(),
            "test": ordered_frame.iloc[cut_validation:].copy(),
        }
        groups = {name: sorted(value["capture_id"].unique().tolist()) for name, value in splits.items()}
        method = "chronological_fallback_single_capture"
    else:
        ordered_frame = frame.reset_index(drop=True)
        cut_train = max(1, int(len(ordered_frame) * 0.60))
        cut_validation = max(cut_train + 1, int(len(ordered_frame) * 0.80))
        splits = {
            "train": ordered_frame.iloc[:cut_train].copy(),
            "validation": ordered_frame.iloc[cut_train:cut_validation].copy(),
            "test": ordered_frame.iloc[cut_validation:].copy(),
        }
        groups = {name: sorted(value["capture_id"].unique().tolist()) for name, value in splits.items()}
        method = "ordered_fallback_without_timestamp"

    metadata = {
        "split_version": SPLIT_VERSION,
        "method": method,
        "seed": seed,
        "groups": groups,
        "row_counts": {name: int(value.shape[0]) for name, value in splits.items()},
        "label_distributions": {
            name: value["canonical_label"].value_counts(dropna=False).to_dict()
            for name, value in splits.items()
        },
        "leakage_notes": [
            "Raw source and destination addresses are anonymized and excluded from model features.",
            "Capture groups are held out when at least three captures are available.",
            "A single capture uses chronological ordering and must not be described as a capture holdout.",
        ],
    }
    return splits, metadata


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, default=str) + "\n", encoding="utf-8")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _write_table(frame: pd.DataFrame, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    frame.to_parquet(path, index=False, compression="zstd")


def prepare_cicids2017(
    input_dir: str | Path,
    output_dir: str | Path = "data",
    sample_rows: int | None = None,
    seed: int = 42,
    export_csv: bool = False,
) -> dict[str, Any]:
    """Prepare CIC-IDS2017 CSVs into canonical tables and provenance manifests."""

    input_path = Path(input_dir).resolve()
    data_root = Path(output_dir).resolve()
    files = discover_csv_files(input_path)
    salt = f"netsentinel-cicids2017-v{SCHEMA_VERSION}-seed-{seed}"
    frames: list[pd.DataFrame] = []
    quality_records: list[dict[str, Any]] = []
    for path in files:
        frame, quality = _clean_frame(path, _read_source(path, sample_rows, seed), salt)
        frames.append(frame)
        quality_records.append(quality)

    combined = pd.concat(frames, ignore_index=True, sort=False)
    canonical_path = data_root / "processed" / "canonical" / "cicids2017_flows.parquet"
    _write_table(combined, canonical_path)
    csv_path: Path | None = None
    if export_csv:
        csv_path = canonical_path.with_suffix(".csv")
        combined.to_csv(csv_path, index=False)

    splits, split_metadata = _split_frame(combined, seed)
    split_paths: dict[str, Path] = {}
    for name, split in splits.items():
        path = data_root / "processed" / name / f"cicids2017_{name}.parquet"
        _write_table(split, path)
        split_paths[name] = path

    manifest_dir = data_root / "artifacts" / "manifests"
    quality_dir = data_root / "reports" / "quality"
    profile_dir = data_root / "reports" / "profiling"
    retrieval_metadata_path = input_path / "download_metadata.json"
    retrieval_metadata: dict[str, Any] = {}
    if retrieval_metadata_path.is_file():
        retrieval_metadata = json.loads(retrieval_metadata_path.read_text(encoding="utf-8-sig"))
    output_files = [canonical_path, *split_paths.values()]
    if csv_path:
        output_files.append(csv_path)
    manifest = {
        "dataset_name": DATASET_NAME,
        "source_url": SOURCE_URL,
        "official_or_mirror": retrieval_metadata.get("source_type", "local_unverified"),
        "retrieval_timestamp_utc": retrieval_metadata.get("retrieval_timestamp_utc"),
        "preparation_timestamp_utc": utc_now(),
        "original_filename": [path.name for path in files],
        "local_path": [str(path) for path in files],
        "file_size_bytes": {str(path): path.stat().st_size for path in files},
        "sha256": {str(path): _sha256(path) for path in files},
        "license_or_terms_note": "Use the official CIC terms and cite Sharafaldin et al. (2018).",
        "raw_schema": {record["source_file"]: record["original_columns"] for record in quality_records},
        "row_count": int(len(combined)),
        "label_distribution": combined["canonical_label"].value_counts(dropna=False).to_dict(),
        "capture_ids": sorted(combined["capture_id"].unique().tolist()),
        "scenario_ids": [],
        "preprocessing_version": SCHEMA_VERSION,
        "canonical_schema_version": SCHEMA_VERSION,
        "split_version": SPLIT_VERSION,
        "limitations": [
            "CIC-IDS2017 labels do not directly cover every SIH threat class.",
            "Capture and feature definitions differ from other public datasets.",
            "Anonymized identities are for consistent analysis, not attribution.",
        ],
        "prepared_output_sha256": {str(path): _sha256(path) for path in output_files},
        "retrieval_metadata": retrieval_metadata,
    }
    _write_json(manifest_dir / "cicids2017_manifest.json", manifest)
    _write_json(manifest_dir / "cicids2017_split_manifest.json", split_metadata)
    profile = {
        "dataset_name": DATASET_NAME,
        "schema_version": SCHEMA_VERSION,
        "row_count": int(len(combined)),
        "column_count": int(len(combined.columns)),
        "columns": {column: str(dtype) for column, dtype in combined.dtypes.items()},
        "missing_values": {column: int(value) for column, value in combined.isna().sum().items()},
        "label_distribution": manifest["label_distribution"],
    }
    _write_json(profile_dir / "cicids2017_profile.json", profile)
    quality_lines = [
        "# CIC-IDS2017 data-quality report",
        "",
        f"Prepared at: `{manifest['preparation_timestamp_utc']}`",
        f"Rows written: `{len(combined)}`",
        f"Files discovered: `{len(files)}`",
        "",
        "## Cleaning counters",
        "",
        "| Source file | Input rows | Output rows | Infinity replacements | Numeric coercions | Nulls filled | Exact duplicates removed |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for record in quality_records:
        quality_lines.append(
            f"| {record['source_file']} | {record['source_rows']} | {record['output_rows']} | "
            f"{record['infinity_replacements']} | {record['numeric_coercions_to_null']} | "
            f"{record['nulls_filled']} | {record['duplicate_rows_removed']} |"
        )
    quality_lines.extend([
        "",
        "## Label policy",
        "",
        "Only explicit CIC labels are mapped. Unrecognized labels remain `unknown`; no substring-based label inference is used.",
        "",
        "## Split policy",
        "",
        f"Method: `{split_metadata['method']}`. See `cicids2017_split_manifest.json` for group membership and limitations.",
    ])
    (quality_dir / "cicids2017_quality_report.md").parent.mkdir(parents=True, exist_ok=True)
    (quality_dir / "cicids2017_quality_report.md").write_text("\n".join(quality_lines) + "\n", encoding="utf-8")
    return {
        "manifest": manifest,
        "split_manifest": split_metadata,
        "quality": quality_records,
        "outputs": [str(path) for path in output_files],
    }


def build_parser() -> argparse.ArgumentParser:
    """Build the preparation command-line parser."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input-dir", required=True, help="Directory containing CIC CSV files")
    parser.add_argument("--output-dir", default="data", help="Repository data directory")
    parser.add_argument("--sample", type=int, help="Read at most this many rows from each CSV")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--export-csv", action="store_true", help="Also write a CSV export")
    return parser


def main() -> int:
    """Run the local-only factory command."""

    args = build_parser().parse_args()
    if args.sample is not None and args.sample <= 0:
        raise SystemExit("--sample must be a positive integer")
    result = prepare_cicids2017(args.input_dir, args.output_dir, args.sample, args.seed, args.export_csv)
    print(json.dumps({"status": "prepared", "outputs": result["outputs"]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
