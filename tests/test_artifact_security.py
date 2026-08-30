"""Security checks for trusted Python artifact loading."""

from __future__ import annotations

import hashlib

import pytest

from netsentinel.models.artifact_security import validate_trusted_artifact


def test_artifact_checksum_and_containment(tmp_path):
    root = tmp_path / "trusted"
    root.mkdir()
    artifact = root / "preprocessing.joblib"
    artifact.write_bytes(b"trusted")
    digest = hashlib.sha256(b"trusted").hexdigest()
    assert validate_trusted_artifact(artifact, root, digest) == artifact.resolve()


def test_artifact_outside_trusted_root_is_rejected(tmp_path):
    root = tmp_path / "trusted"
    root.mkdir()
    artifact = tmp_path / "outside.joblib"
    artifact.write_bytes(b"untrusted")
    digest = hashlib.sha256(b"untrusted").hexdigest()
    with pytest.raises(ValueError):
        validate_trusted_artifact(artifact, root, digest)
