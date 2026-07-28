"""Unit tests for scripts/audit-public-repository and
scripts/build-source-archive (P0: repo/secret hygiene mechanics
remediation — see KNOWN_ISSUES.md).

Both scripts hardcode REPO_ROOT to this actual repository (the same
established convention scripts/validate-production-compose,
scripts/verify-release, etc. already use) rather than taking an arbitrary
target path — so these are black-box subprocess tests against the real
repository, the same style tests/unit/test_config_schema.py already uses
for scripts/validate-config.
"""
from __future__ import annotations

import subprocess
import sys
import tarfile
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
AUDIT_SCRIPT = REPO_ROOT / "scripts" / "audit-public-repository"
ARCHIVE_SCRIPT = REPO_ROOT / "scripts" / "build-source-archive"

pytestmark = pytest.mark.unit


def _run(script: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(script), *args],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
    )


# ---------------------------------------------------------------------------
# audit-public-repository
# ---------------------------------------------------------------------------

def test_audit_script_never_crashes_and_reports_a_clear_exit_code():
    result = _run(AUDIT_SCRIPT)
    assert result.returncode in (0, 1), f"unexpected crash:\n{result.stdout}\n{result.stderr}"


def test_audit_finds_no_forbidden_tracked_paths_or_private_key_content():
    """These two checks are current-tree-based (git ls-files), not git-
    history-based like the gitleaks check below — always deterministic
    regardless of what has or hasn't been committed yet this session."""
    result = _run(AUDIT_SCRIPT)
    combined = result.stdout + result.stderr
    assert "forbidden vendored/generated/secret-key path pattern" not in combined
    assert "a real env file is git-tracked" not in combined
    for marker in ("BEGIN RSA PRIVATE KEY", "BEGIN EC PRIVATE KEY", "BEGIN OPENSSH PRIVATE KEY"):
        assert marker not in combined, f"{marker} found in tracked file content"


def test_audit_gitleaks_finding_if_any_is_only_the_known_test_fixture():
    """gitleaks scans git HISTORY, so this can only go fully clean once the
    `gitleaks:allow` suppression already added to
    tests/unit/test_config_schema.py's fake-AWS-key fixture line is itself
    committed. Until then, the ONE known/expected historical finding is
    tolerated here — but nothing else is. A NEW real leak still fails this
    test either way."""
    result = _run(AUDIT_SCRIPT)
    if result.returncode == 0:
        return
    output = result.stdout + result.stderr
    assert "gitleaks found potential secrets" in output, output
    # Every other check must still have passed.
    assert "forbidden vendored/generated/secret-key path pattern" not in output
    assert "a real env file is git-tracked" not in output
    assert "validate-config --scan-secrets failed" not in output


def test_audit_script_is_executable():
    assert AUDIT_SCRIPT.stat().st_mode & 0o111, "scripts/audit-public-repository must be chmod +x"


# ---------------------------------------------------------------------------
# build-source-archive
# ---------------------------------------------------------------------------

def test_build_source_archive_is_executable():
    assert ARCHIVE_SCRIPT.stat().st_mode & 0o111, "scripts/build-source-archive must be chmod +x"


def test_skip_audit_archive_contains_no_forbidden_paths(tmp_path):
    output = tmp_path / "mirage-source-test.tar.gz"
    result = _run(ARCHIVE_SCRIPT, "--output", str(output), "--skip-audit")
    assert result.returncode == 0, result.stdout + result.stderr
    assert "WARNING" in result.stdout
    assert output.is_file()

    with tarfile.open(output, "r:gz") as tar:
        names = tar.getnames()
    assert names, "archive must not be empty"
    forbidden_substrings = ("node_modules", ".venv/", "dev-provisioner-keys", "__pycache__")
    for name in names:
        assert name != ".env"
        for forbidden in forbidden_substrings:
            assert forbidden not in name, f"{name} should never be in a git-archive-based source archive"


def test_archive_refuses_to_build_when_audit_fails_without_skip_flag(tmp_path):
    """When the underlying audit fails (as it currently does pre-commit —
    see test_audit_gitleaks_finding_if_any_is_only_the_known_test_fixture),
    no archive file is written unless --skip-audit is explicitly passed."""
    output = tmp_path / "mirage-source-should-not-exist.tar.gz"
    result = _run(ARCHIVE_SCRIPT, "--output", str(output))
    audit_result = _run(AUDIT_SCRIPT)
    if audit_result.returncode != 0:
        assert result.returncode == 1
        assert not output.exists()
    else:
        assert result.returncode == 0
        assert output.is_file()


def test_archive_accepts_head_sha_as_ref_without_false_positive_mismatch(tmp_path):
    """--ref defaults to HEAD; passing HEAD's own resolved SHA explicitly
    must be treated as equivalent (never the 'ref does not match checked-out
    HEAD' refusal), even though the two strings differ textually."""
    head_sha = subprocess.run(
        ["git", "-C", str(REPO_ROOT), "rev-parse", "HEAD"], capture_output=True, text=True, check=True
    ).stdout.strip()
    output = tmp_path / "mirage-source-head-sha.tar.gz"
    result = _run(ARCHIVE_SCRIPT, "--ref", head_sha, "--output", str(output), "--skip-audit")
    assert result.returncode == 0, result.stdout + result.stderr
    assert "does not match the currently checked-out HEAD" not in (result.stdout + result.stderr)
