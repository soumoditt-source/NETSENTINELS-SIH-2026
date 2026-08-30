"""Security checks for repository-controlled Python model artifacts."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any


def sha256_file(path: str | Path) -> str:
    """Calculate SHA-256 in bounded chunks."""

    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def validate_trusted_artifact(
    path: str | Path,
    trusted_root: str | Path,
    expected_sha256: str,
) -> Path:
    """Validate containment and checksum before a caller deserializes an artifact."""

    artifact = Path(path).resolve()
    root = Path(trusted_root).resolve()
    if root != artifact and root not in artifact.parents:
        raise ValueError("model artifact is outside the trusted artifact directory")
    if not artifact.is_file():
        raise FileNotFoundError(artifact)
    actual = sha256_file(artifact)
    if actual.lower() != expected_sha256.lower():
        raise ValueError("model artifact SHA-256 does not match the trusted manifest")
    return artifact


def load_trusted_joblib(
    path: str | Path,
    trusted_root: str | Path,
    expected_sha256: str,
) -> Any:
    """Load joblib only after repository containment and checksum validation."""

    artifact = validate_trusted_artifact(path, trusted_root, expected_sha256)
    if artifact.suffix.lower() not in {".joblib", ".pkl"}:
        raise ValueError("only .joblib and .pkl files can be loaded by this helper")
    import joblib

    return joblib.load(artifact)
