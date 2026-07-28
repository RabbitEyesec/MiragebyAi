"""Clean-room proof that a Mirage release ZIP is actually standalone
(Priority 10): build it once from this source tree, then work ONLY from an
isolated copy of the extracted ZIP plus a brand-new virtualenv — never
touching this repository's own installed `mirage_common`/`mirage_contracts`
packages, never referencing this repository's path at all.

This is a real, previously-broken guarantee: every release script
(`scripts/install-server` etc.) does `from mirage_common... import ...`,
but those packages existed nowhere in the ZIP as loose source before this
fix — only inside the now-bundled `packages/mirage-*.whl`. Without that
wheel and the `scripts/install-mirage-package` step that installs it, those
scripts would raise `ModuleNotFoundError` on any host that has never run
`pip install -e .` against this source tree — which is every real target
server, and is exactly the failure mode reproduced (and confirmed) while
diagnosing this gap.

Marked `integration` (not `unit`) because it does real filesystem
isolation, a real `python -m venv`, and a real `pip install` of the release
wheel's dependencies from PyPI — meaningfully slower and network-dependent,
unlike the fast hermetic unit suite.
"""
from __future__ import annotations

import subprocess
import sys
import zipfile
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from mirage_common.release import build_release

pytestmark = pytest.mark.integration

REPO_ROOT = Path(__file__).resolve().parents[2]


def _signing_key(path: Path) -> Path:
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
    )
    return path


def test_release_scripts_run_using_only_the_extracted_zip_and_a_fresh_venv(tmp_path: Path) -> None:
    # 1. Build the release from the real source tree (this is the only step
    #    allowed to know this repository's path).
    key_path = _signing_key(tmp_path / "release-key.pem")
    package_path = tmp_path / "mirage-release.zip"
    result = build_release(REPO_ROOT, version="1.0.0-clean-room", output=package_path, signing_key=key_path)
    assert result["file_count"] >= 20

    with zipfile.ZipFile(package_path) as archive:
        wheel_names = [name for name in archive.namelist() if name.startswith("packages/mirage-") and name.endswith(".whl")]
        assert len(wheel_names) == 1, "exactly one bundled Mirage wheel is expected"

    # 2. Isolated clean room: an empty directory containing ONLY the
    #    extracted ZIP contents — nothing from REPO_ROOT is copied or
    #    referenced from here on.
    clean_room = tmp_path / "clean-room"
    clean_room.mkdir()
    with zipfile.ZipFile(package_path) as archive:
        archive.extractall(clean_room)

    # 3. A brand-new virtualenv, unrelated to this repo's own .venv (which
    #    has mirage_common editable-installed and would silently mask the
    #    bug this test exists to catch).
    fresh_venv = tmp_path / "fresh-venv"
    subprocess.run([sys.executable, "-m", "venv", str(fresh_venv)], check=True)
    fresh_python = fresh_venv / "bin" / "python"

    # Confirm the bug this test guards against: mirage_common is NOT
    # importable in the fresh venv before the wheel is installed.
    pre_install = subprocess.run(
        [str(fresh_python), "-c", "import mirage_common"], capture_output=True, text=True, cwd=clean_room
    )
    assert pre_install.returncode != 0, "test setup invariant broken: mirage_common should not be importable yet"

    # 4. Run the release's OWN bootstrap step, using ONLY files inside the
    #    clean room — this is scripts/install-mirage-package, run exactly
    #    as the server installer's "python-package" step would run it.
    install_result = subprocess.run(
        [str(fresh_python), "scripts/install-mirage-package", "--venv", str(fresh_venv)],
        capture_output=True, text=True, cwd=clean_room,
    )
    assert install_result.returncode == 0, install_result.stderr

    # 5. Now mirage_common resolves from the WHEEL just installed into the
    #    fresh venv — not from REPO_ROOT.
    post_install = subprocess.run(
        [str(fresh_python), "-c", "import mirage_common; print(mirage_common.__file__)"],
        capture_output=True, text=True, cwd=clean_room,
    )
    assert post_install.returncode == 0, post_install.stderr
    resolved_path = post_install.stdout.strip()
    assert str(REPO_ROOT) not in resolved_path
    assert str(fresh_venv) in resolved_path

    # 6. The actual release script now runs standalone, from the clean
    #    room, using the fresh venv's interpreter — no reference to
    #    REPO_ROOT anywhere in this invocation.
    help_result = subprocess.run(
        [str(fresh_python), "scripts/install-server", "--help"],
        capture_output=True, text=True, cwd=clean_room,
    )
    assert help_result.returncode == 0, help_result.stderr
    assert "--environment" in help_result.stdout
