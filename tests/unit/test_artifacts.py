from __future__ import annotations

import io
import zipfile
from pathlib import Path

import pytest

from mirage_common.artifacts import (
    ArchivePolicyError,
    ArtifactError,
    ArtifactScannerConfig,
    inspect_archive,
    observation_levels,
    stage_upload,
    validate_deployment,
)


def _zip(path: Path, entries: list[tuple[str, bytes]]) -> None:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in entries:
            archive.writestr(name, data)


def test_streaming_upload_limit_and_hash(tmp_path: Path) -> None:
    staged = stage_upload(
        io.BytesIO(b"clean"),
        original_filename="../../bait.txt",
        quarantine_dir=tmp_path,
        max_upload_mb=1,
    )
    assert staged.sanitised_filename == "bait.txt"
    assert staged.size_bytes == 5
    with pytest.raises(ArtifactError):
        stage_upload(
            io.BytesIO(b"x" * (1024 * 1024 + 1)),
            original_filename="large.bin",
            quarantine_dir=tmp_path,
            max_upload_mb=1,
        )


def test_archive_path_traversal_and_bomb_rejected(tmp_path: Path) -> None:
    traversal = tmp_path / "traversal.zip"
    _zip(traversal, [("../escape", b"x")])
    with pytest.raises(ArchivePolicyError, match="traversal"):
        inspect_archive(traversal, ArtifactScannerConfig())
    bomb = tmp_path / "bomb.zip"
    _zip(bomb, [("huge.txt", b"0" * 1_000_000)])
    with pytest.raises(ArchivePolicyError, match="ratio"):
        inspect_archive(bomb, ArtifactScannerConfig(max_compression_ratio=2))


def test_observation_levels_are_honest() -> None:
    assert observation_levels("text/plain") == ("L1", "L5")
    assert observation_levels("application/x-dosexec") == ("L1", "L2")
    assert "L3" in observation_levels("application/pdf", canary_enabled=True)


def test_deployment_rejects_wrong_hash_and_disallowed_destination(tmp_path: Path) -> None:
    with pytest.raises(ArtifactError, match="outside"):
        validate_deployment(
            scan_status="APPROVED",
            approved_for_deployment=True,
            classification="INERT",
            destination=str(tmp_path.parent / "outside"),
            allowed_roots=(tmp_path / "inside",),
            expected_sha256="a",
            observed_sha256="a",
        )
    with pytest.raises(ArtifactError, match="SHA"):
        validate_deployment(
            scan_status="APPROVED",
            approved_for_deployment=True,
            classification="INERT",
            destination=str(tmp_path / "inside" / "bait"),
            allowed_roots=(tmp_path / "inside",),
            expected_sha256="a",
            observed_sha256="b",
        )
