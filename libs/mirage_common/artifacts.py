"""Stage 7 artifact streaming limits, archive controls, scanner, and deployment policy."""
from __future__ import annotations

import hashlib
import mimetypes
import os
import re
import shutil
import subprocess
import tarfile
import tempfile
import time
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import BinaryIO

from mirage_common.evidence import CHUNK_SIZE, sanitise_filename


class ArtifactError(Exception):
    pass


class ArchivePolicyError(ArtifactError):
    pass


@dataclass(frozen=True)
class ArtifactScannerConfig:
    max_upload_mb: int = 250
    max_archive_depth: int = 3
    max_archive_members: int = 1000
    max_expanded_mb: int = 500
    max_compression_ratio: float = 100.0
    per_member_max_mb: int = 250
    scan_timeout_seconds: int = 120
    clamav_timeout_seconds: int = 60
    yara_timeout_seconds: int = 30
    oletools_timeout_seconds: int = 30
    yara_rules_path: str | None = None
    clamav_database_path: str | None = None


@dataclass(frozen=True)
class StagedArtifact:
    path: Path
    sanitised_filename: str
    size_bytes: int
    sha256: str


@dataclass(frozen=True)
class ScanResult:
    status: str
    detected_type: str
    clamav_result: dict
    yara_matches: tuple[str, ...]
    oletools_result: dict
    archive_metadata: dict
    observation_levels: tuple[str, ...]
    limitations: tuple[str, ...]


def stage_upload(
    stream: BinaryIO,
    *,
    original_filename: str,
    quarantine_dir: Path,
    max_upload_mb: int = 250,
) -> StagedArtifact:
    quarantine_dir.mkdir(parents=True, exist_ok=True)
    safe_name = sanitise_filename(original_filename)
    assert safe_name is not None
    fd, temp_name = tempfile.mkstemp(prefix="upload-", suffix=f"-{safe_name}", dir=quarantine_dir)
    digest = hashlib.sha256()
    size = 0
    max_bytes = max_upload_mb * 1024 * 1024
    try:
        with os.fdopen(fd, "wb") as target:
            while True:
                chunk = stream.read(CHUNK_SIZE)
                if not chunk:
                    break
                size += len(chunk)
                if size > max_bytes:
                    raise ArtifactError(f"artifact exceeds {max_upload_mb} MB")
                digest.update(chunk)
                target.write(chunk)
        return StagedArtifact(Path(temp_name), safe_name, size, digest.hexdigest())
    except Exception:
        Path(temp_name).unlink(missing_ok=True)
        raise


def _safe_member_name(name: str) -> str:
    normalised = name.replace("\\", "/")
    path = PurePosixPath(normalised)
    if path.is_absolute() or ".." in path.parts or re.match(r"^[A-Za-z]:", normalised):
        raise ArchivePolicyError(f"archive path traversal rejected: {name!r}")
    return str(path)


@dataclass
class _ArchiveTotals:
    members: int = 0
    expanded_bytes: int = 0
    compressed_bytes: int = 0
    max_depth_seen: int = 0


def inspect_archive(path: Path, config: ArtifactScannerConfig) -> dict:
    totals = _ArchiveTotals()
    _inspect_archive_recursive(path, config, totals, depth=1)
    ratio = totals.expanded_bytes / max(1, totals.compressed_bytes)
    if ratio > config.max_compression_ratio:
        raise ArchivePolicyError(
            f"archive compression ratio {ratio:.1f} exceeds {config.max_compression_ratio}"
        )
    return {
        "member_count": totals.members,
        "expanded_size_bytes": totals.expanded_bytes,
        "compressed_size_bytes": totals.compressed_bytes,
        "compression_ratio": round(ratio, 3),
        "max_depth": totals.max_depth_seen,
    }


def _inspect_archive_recursive(
    path: Path,
    config: ArtifactScannerConfig,
    totals: _ArchiveTotals,
    *,
    depth: int,
) -> None:
    if depth > config.max_archive_depth:
        raise ArchivePolicyError("maximum archive nesting depth exceeded")
    totals.max_depth_seen = max(totals.max_depth_seen, depth)
    max_member = config.per_member_max_mb * 1024 * 1024
    max_expanded = config.max_expanded_mb * 1024 * 1024
    with tempfile.TemporaryDirectory(prefix="mirage-archive-") as temp_dir:
        root = Path(temp_dir)
        names: set[str] = set()
        if zipfile.is_zipfile(path):
            try:
                archive = zipfile.ZipFile(path)
            except RuntimeError as exc:
                raise ArchivePolicyError("password-protected archive rejected") from exc
            with archive:
                for info in archive.infolist():
                    name = _safe_member_name(info.filename)
                    if name in names:
                        raise ArchivePolicyError(f"duplicate archive member name: {name}")
                    names.add(name)
                    mode = (info.external_attr >> 16) & 0o170000
                    if mode == 0o120000:
                        raise ArchivePolicyError(f"archive symlink rejected: {name}")
                    if info.flag_bits & 0x1:
                        raise ArchivePolicyError("password-protected archive rejected")
                    if info.is_dir():
                        continue
                    _add_member(config, totals, info.file_size, info.compress_size)
                    if info.file_size > max_member:
                        raise ArchivePolicyError("archive member exceeds per-member size limit")
                    destination = root / name
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    with archive.open(info) as source, destination.open("wb") as target:
                        shutil.copyfileobj(source, target, CHUNK_SIZE)
                    if zipfile.is_zipfile(destination) or tarfile.is_tarfile(destination):
                        _inspect_archive_recursive(destination, config, totals, depth=depth + 1)
        elif tarfile.is_tarfile(path):
            with tarfile.open(path) as tar_archive:
                for member in tar_archive.getmembers():
                    name = _safe_member_name(member.name)
                    if name in names:
                        raise ArchivePolicyError(f"duplicate archive member name: {name}")
                    names.add(name)
                    if member.issym() or member.islnk():
                        raise ArchivePolicyError(f"archive link rejected: {name}")
                    if not member.isfile():
                        continue
                    _add_member(config, totals, member.size, max(1, member.size))
                    if member.size > max_member:
                        raise ArchivePolicyError("archive member exceeds per-member size limit")
                    tar_source = tar_archive.extractfile(member)
                    if tar_source is None:
                        raise ArchivePolicyError(f"unable to read archive member: {name}")
                    destination = root / name
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    with tar_source, destination.open("wb") as target:
                        shutil.copyfileobj(tar_source, target, CHUNK_SIZE)
                    if zipfile.is_zipfile(destination) or tarfile.is_tarfile(destination):
                        _inspect_archive_recursive(destination, config, totals, depth=depth + 1)
        else:
            return
        if totals.expanded_bytes > max_expanded:
            raise ArchivePolicyError("archive expanded-size limit exceeded")


def _add_member(
    config: ArtifactScannerConfig, totals: _ArchiveTotals, expanded: int, compressed: int
) -> None:
    totals.members += 1
    totals.expanded_bytes += expanded
    totals.compressed_bytes += max(1, compressed)
    if totals.members > config.max_archive_members:
        raise ArchivePolicyError("archive member-count limit exceeded")
    ratio = totals.expanded_bytes / max(1, totals.compressed_bytes)
    if ratio > config.max_compression_ratio:
        raise ArchivePolicyError("archive compression-ratio limit exceeded")


def _run_tool(args: list[str], timeout: float) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)


def detect_type(path: Path) -> str:
    if shutil.which("file"):
        result = _run_tool(["file", "--brief", "--mime-type", str(path)], 10)
        if result.returncode == 0:
            return result.stdout.strip()
    return mimetypes.guess_type(path.name)[0] or "application/octet-stream"


def observation_levels(media_type: str, *, canary_enabled: bool = False) -> tuple[str, ...]:
    levels = ["L1"]
    executable = media_type in {
        "application/x-dosexec",
        "application/x-executable",
        "application/x-mach-binary",
        "application/x-msdownload",
    }
    if executable:
        levels.append("L2")
    if canary_enabled:
        levels.append("L3")
    if media_type in {
        "application/zip",
        "application/pdf",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    }:
        levels.append("L4")
    if media_type in {"application/pdf", "text/plain", "text/html"}:
        levels.append("L5")
    return tuple(levels)


class ArtifactScanner:
    def __init__(self, config: ArtifactScannerConfig) -> None:
        self.config = config

    def scan(self, staged: StagedArtifact, *, canary_enabled: bool = False) -> ScanResult:
        deadline = time.monotonic() + self.config.scan_timeout_seconds

        def remaining(component_timeout: int) -> float:
            available = deadline - time.monotonic()
            if available <= 0:
                raise subprocess.TimeoutExpired("total artifact scan", 0)
            return min(float(component_timeout), available)

        detected = detect_type(staged.path)
        archive_meta: dict = {}
        try:
            if zipfile.is_zipfile(staged.path) or tarfile.is_tarfile(staged.path):
                archive_meta = inspect_archive(staged.path, self.config)
        except ArchivePolicyError as exc:
            return ScanResult(
                "MALICIOUS",
                detected,
                {"status": "NOT_RUN", "reason": "archive policy rejected first"},
                (),
                {},
                {"error": str(exc)},
                observation_levels(detected, canary_enabled=canary_enabled),
                (str(exc),),
            )

        limitations: list[str] = []
        try:
            clamav = self._clamav(
                staged.path, timeout=remaining(self.config.clamav_timeout_seconds)
            )
            yara = self._yara(
                staged.path, timeout=remaining(self.config.yara_timeout_seconds)
            )
            ole = self._oletools(
                staged.path,
                detected,
                timeout=remaining(self.config.oletools_timeout_seconds),
            )
        except subprocess.TimeoutExpired:
            return ScanResult(
                "FAILED",
                detected,
                {"status": "FAILED", "detail": "total artifact scan timed out"},
                (),
                {"status": "NOT_RUN"},
                archive_meta,
                observation_levels(detected, canary_enabled=canary_enabled),
                ("total artifact scan timed out",),
            )
        if clamav["status"] == "MALICIOUS":
            status = "MALICIOUS"
        elif clamav["status"] == "FAILED" or yara is None or ole.get("status") == "FAILED":
            status = "FAILED"
        elif yara:
            status = "SUSPICIOUS"
        else:
            status = "CLEAN"
        if clamav["status"] == "FAILED":
            limitations.append(clamav["detail"])
        if yara is None:
            limitations.append("YARA scanner unavailable or rules not configured")
            yara_matches: tuple[str, ...] = ()
        else:
            yara_matches = tuple(yara)
        if ole.get("status") == "FAILED":
            limitations.append(ole["detail"])
        return ScanResult(
            status,
            detected,
            clamav,
            yara_matches,
            ole,
            archive_meta,
            observation_levels(detected, canary_enabled=canary_enabled),
            tuple(limitations),
        )

    def _clamav(self, path: Path, *, timeout: float) -> dict:
        executable = shutil.which("clamscan")
        if not executable:
            return {"status": "FAILED", "detail": "clamscan executable unavailable"}
        args = [executable, "--no-summary", "--infected"]
        if self.config.clamav_database_path:
            args.extend(["--database", self.config.clamav_database_path])
        args.append(str(path))
        try:
            result = _run_tool(
                args,
                timeout,
            )
        except subprocess.TimeoutExpired:
            return {"status": "FAILED", "detail": "ClamAV scan timed out"}
        if result.returncode == 0:
            return {"status": "CLEAN", "detail": result.stdout.strip()}
        if result.returncode == 1:
            return {"status": "MALICIOUS", "detail": result.stdout.strip()}
        return {"status": "FAILED", "detail": (result.stderr or result.stdout).strip()[:1024]}

    def _yara(self, path: Path, *, timeout: float) -> list[str] | None:
        executable = shutil.which("yara")
        if not executable or not self.config.yara_rules_path:
            return None
        try:
            result = _run_tool(
                [executable, "-r", self.config.yara_rules_path, str(path)],
                timeout,
            )
        except subprocess.TimeoutExpired:
            return None
        if result.returncode not in (0, 1):
            return None
        return sorted({line.split()[0] for line in result.stdout.splitlines() if line.strip()})

    def _oletools(self, path: Path, detected_type: str, *, timeout: float) -> dict:
        office = "officedocument" in detected_type or detected_type in {
            "application/msword",
            "application/vnd.ms-excel",
            "application/vnd.ms-powerpoint",
            "application/x-ole-storage",
        }
        if not office:
            return {"status": "NOT_APPLICABLE"}
        executable = shutil.which("oleid")
        if not executable:
            return {"status": "FAILED", "detail": "oleid executable unavailable for Office file"}
        try:
            result = _run_tool([executable, str(path)], timeout)
        except subprocess.TimeoutExpired:
            return {"status": "FAILED", "detail": "oletools scan timed out"}
        return {
            "status": "COMPLETE" if result.returncode == 0 else "FAILED",
            "detail": (result.stdout or result.stderr)[:4096],
        }


def validate_deployment(
    *,
    scan_status: str,
    approved_for_deployment: bool,
    classification: str,
    destination: str,
    allowed_roots: tuple[Path, ...],
    expected_sha256: str,
    observed_sha256: str,
) -> None:
    if scan_status not in {"CLEAN", "APPROVED"} or not approved_for_deployment:
        raise ArtifactError("artifact is not approved for deployment")
    if classification not in {"INERT", "CONTROLLED"}:
        raise ArtifactError("only inert or controlled artifacts may deploy")
    destination_path = Path(destination).resolve(strict=False)
    if not any(destination_path.is_relative_to(root.resolve(strict=False)) for root in allowed_roots):
        raise ArtifactError("destination is outside approved mutation roots")
    if expected_sha256 != observed_sha256:
        raise ArtifactError("downloaded artifact SHA-256 mismatch")
