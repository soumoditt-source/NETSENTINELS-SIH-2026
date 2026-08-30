"""Explicit, provenance-first CIC-IDS2017 downloader.

The official CIC page requires users to review its terms. The default command
therefore prints the official page and exits unless a user supplies a direct
archive URL they are authorized to retrieve. Downloads are written atomically
and never executed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

OFFICIAL_PAGE = "https://www.unb.ca/cic/datasets/ids-2017.html"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_file(path: Path, expected_sha256: str | None = None) -> dict[str, object]:
    """Return local file integrity information."""

    if not path.is_file():
        raise FileNotFoundError(path)
    digest = _sha256(path)
    return {
        "path": str(path.resolve()),
        "size_bytes": path.stat().st_size,
        "sha256": digest,
        "matches_expected": expected_sha256 is None or digest.lower() == expected_sha256.lower(),
    }


def download_cic_ids2017(
    output_dir: str | Path,
    source_url: str | None = None,
    expected_sha256: str | None = None,
    offline: bool = False,
    sample: int | None = None,
) -> dict[str, object]:
    """Download one user-authorized archive and write a provenance record."""

    destination = Path(output_dir).resolve()
    destination.mkdir(parents=True, exist_ok=True)
    if offline:
        raise RuntimeError("Offline mode forbids downloads; use prepare_cicids2017 on local CSVs")
    if not source_url:
        raise RuntimeError(
            f"No direct archive URL supplied. Review the official source first: {OFFICIAL_PAGE}"
        )
    parsed = urllib.parse.urlparse(source_url)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("source URL must use http:// or https://")

    filename = Path(parsed.path).name or "cicids2017.download"
    final_path = destination / filename
    partial_path = destination / f".{filename}.part"
    if final_path.exists():
        raise FileExistsError(f"Refusing to overwrite existing file: {final_path}")
    try:
        with urllib.request.urlopen(source_url, timeout=60) as response, partial_path.open("wb") as target:
            shutil.copyfileobj(response, target, length=1024 * 1024)
        if partial_path.stat().st_size == 0:
            raise RuntimeError("Downloaded file is empty")
        partial_path.replace(final_path)
    except Exception:
        partial_path.unlink(missing_ok=True)
        raise

    integrity = verify_file(final_path, expected_sha256)
    if not integrity["matches_expected"]:
        final_path.unlink(missing_ok=True)
        raise RuntimeError("SHA-256 mismatch; partial or unexpected data was removed")
    metadata = {
        "dataset_name": "CIC-IDS2017",
        "source_url": source_url,
        "official_source_page": OFFICIAL_PAGE,
        "retrieval_timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "sample_requested": sample,
        "file": integrity,
        "execution_policy": "downloaded files are never executed",
    }
    (destination / "download_metadata.json").write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
    return metadata


def build_parser() -> argparse.ArgumentParser:
    """Build an explicit subcommand parser."""

    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    download = subparsers.add_parser("download", help="download one authorized archive")
    download.add_argument("--output-dir", default="data/raw/cicids2017")
    download.add_argument("--source-url", help="direct archive URL; official landing page is not an archive")
    download.add_argument("--sha256")
    download.add_argument("--sample", type=int)
    download.add_argument("--offline", action="store_true")
    verify = subparsers.add_parser("verify", help="verify one local file")
    verify.add_argument("path")
    verify.add_argument("--sha256")
    return parser


def main(argv: list[str] | None = None) -> int:
    """Execute download or verification without implicit network access."""

    args = build_parser().parse_args(argv)
    if args.command == "verify":
        print(json.dumps(verify_file(Path(args.path), args.sha256), indent=2))
        return 0
    if args.sample is not None and args.sample <= 0:
        raise SystemExit("--sample must be a positive integer")
    print(f"Official source: {OFFICIAL_PAGE}")
    result = download_cic_ids2017(args.output_dir, args.source_url, args.sha256, args.offline, args.sample)
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (FileExistsError, FileNotFoundError, RuntimeError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(2)
