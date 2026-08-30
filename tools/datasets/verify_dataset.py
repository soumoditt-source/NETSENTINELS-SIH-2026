"""Verify local dataset files and emit SHA-256 metadata."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


def _hash(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> int:
    """Hash local files without opening archives or executing content."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input_dir")
    parser.add_argument("--output", default="data/artifacts/manifests/local_dataset_hashes.json")
    args = parser.parse_args()
    root = Path(args.input_dir).resolve()
    if not root.is_dir():
        raise SystemExit(f"input directory does not exist: {root}")
    files = sorted(path for path in root.rglob("*") if path.is_file())
    result = {"root": str(root), "files": {str(path.relative_to(root)): {"size_bytes": path.stat().st_size, "sha256": _hash(path)} for path in files}}
    destination = Path(args.output)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
