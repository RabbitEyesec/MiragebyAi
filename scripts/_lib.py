"""Shared helpers for scripts/{doctor,check-prerequisites,validate-config,bootstrap-*}.

Deliberately dependency-light (stdlib only) so these scripts can run before
`pip install -e .` has ever happened — they are the *first* thing a new
contributor runs.
"""
from __future__ import annotations

import json
import os
import secrets
import shutil
import socket
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

DEV_AUTH_CREDENTIALS_PATH = REPO_ROOT / ".dev-auth-keys" / "dev-credentials.json"
ENV_FILE_PATH = REPO_ROOT / ".env"


def load_env_file(path: Path = ENV_FILE_PATH) -> int:
    """Load `.env` into os.environ without overriding anything already set.

    Docker Compose reads `.env` by itself, so the *containers* get whatever is
    in it — but these bootstrap scripts run on the HOST, where nothing puts
    those values into the environment. That was harmless while `.env` was a
    verbatim copy of `.env.example`, because the scripts' fallback defaults
    were the same published literals the containers were using. Once
    `scripts/rotate-dev-credentials` gives each machine its own values, the two
    sides disagree: Keycloak starts with the rotated MIRAGE_KEYCLOAK_ADMIN_PASSWORD
    while `bootstrap-keycloak-realm` still tries the old literal, and admin
    login fails.

    Existing environment variables win, so an explicit `VAR=... script` still
    overrides the file. Returns the number of variables loaded.
    """
    if not path.is_file():
        return 0
    loaded = 0
    for line in path.read_text().splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        name, _, value = stripped.partition("=")
        name = name.strip()
        if not name or name in os.environ:
            continue
        os.environ[name] = value.strip().strip('"').strip("'")
        loaded += 1
    return loaded


def get_or_create_dev_user_password(path: Path = DEV_AUTH_CREDENTIALS_PATH) -> str:
    """Returns the random per-machine password for Mirage's dev Keycloak
    test users (dev-platform-admin, dev-investigator, dev-operator,
    dev-auditor, dev-read-only), generating and persisting one on first use.

    Deliberately NOT a hardcoded literal in tracked source (that was F-02:
    a single shared password committed to the repo) — each clone/machine
    gets its own value, written to a gitignored file
    (`.dev-auth-keys/dev-credentials.json`, 0600) so re-running bootstrap is
    idempotent (existing dev sessions/scripts keep working) rather than
    silently rotating the password and locking out whoever is mid-testing.
    """
    if path.is_file():
        return json.loads(path.read_text())["password"]
    password = secrets.token_urlsafe(18)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"password": password}, indent=2) + "\n")
    path.chmod(0o600)
    return password


class Result:
    __slots__ = ("name", "ok", "detail", "required")

    def __init__(self, name: str, ok: bool, detail: str, required: bool = True):
        self.name = name
        self.ok = ok
        self.detail = detail
        self.required = required


def _color(code: str, text: str) -> str:
    if not sys.stdout.isatty():
        return text
    return f"\033[{code}m{text}\033[0m"


def green(text: str) -> str:
    return _color("32", text)


def red(text: str) -> str:
    return _color("31", text)


def yellow(text: str) -> str:
    return _color("33", text)


def dim(text: str) -> str:
    return _color("2", text)


def run(cmd: list[str], timeout: float = 5.0) -> tuple[int, str]:
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, check=False
        )
        out = (proc.stdout or "") + (proc.stderr or "")
        return proc.returncode, out.strip()
    except FileNotFoundError:
        return 127, "not found"
    except subprocess.TimeoutExpired:
        return 124, "timed out"


def which(tool: str) -> str | None:
    return shutil.which(tool)


def tool_version(tool: str, version_flag: str = "--version") -> Result:
    path = which(tool)
    if not path:
        return Result(tool, False, "not found on PATH")
    code, out = run([tool, version_flag])
    first_line = out.splitlines()[0] if out else "(no output)"
    return Result(tool, code == 0, first_line)


def port_status(host: str, port: int, timeout: float = 0.5) -> bool:
    """True if something is listening on host:port."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def print_table(results: list[Result]) -> bool:
    """Prints a pass/fail table; returns True iff every *required* result passed."""
    all_required_ok = True
    name_width = max((len(r.name) for r in results), default=10) + 2
    for r in results:
        if r.ok:
            mark = green("OK")
        elif r.required:
            mark = red("FAIL")
            all_required_ok = False
        else:
            mark = yellow("WARN")
        print(f"  {r.name.ljust(name_width)} {mark:>6}  {dim(r.detail)}")
    return all_required_ok


def print_header(title: str) -> None:
    print()
    print(title)
    print("-" * len(title))
