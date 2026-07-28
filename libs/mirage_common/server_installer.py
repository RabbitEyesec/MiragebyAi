"""Transactional Ubuntu server installer planning and execution."""
from __future__ import annotations

import argparse
import errno
import hashlib
import json
import os
import platform
import shutil
import socket
import subprocess
import sys
import zipfile
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

import yaml

from mirage_common.release import generate_install_report, verify_release

Operation = Literal[
    "install",
    "validate",
    "upgrade",
    "rollback",
    "repair",
    "status",
    "uninstall",
]
SUPPORTED_OPERATIONS = (
    "install",
    "validate",
    "upgrade",
    "rollback",
    "repair",
    "status",
    "uninstall",
)


@dataclass(frozen=True)
class InstallStep:
    number: int
    step_id: str
    description: str
    command: tuple[str, ...] | None
    destructive: bool = False


@dataclass(frozen=True)
class StepResult:
    step_id: str
    status: str
    started_at: str
    ended_at: str
    detail: str


def server_plan(operation: Operation) -> tuple[InstallStep, ...]:
    common = (
        ("preflight", "Validate Ubuntu OS and architecture", None),
        ("capacity", "Validate CPU, RAM, disk, and filesystem", None),
        ("clock", "Validate clock synchronisation", ("timedatectl", "show")),
        ("dns", "Validate configured service DNS", None),
        ("ports", "Validate required ports", None),
        ("docker", "Install or validate Docker Engine", ("docker", "version")),
        ("compose", "Install or validate Docker Compose", ("docker", "compose", "version")),
        ("firewall", "Validate host firewall policy", ("ufw", "status")),
        ("directories", "Create protected directories and ownership", None),
        ("configuration", "Validate configuration", (".venv/bin/python", "scripts/validate-config")),
        (
            "secret-references",
            "Validate secret references and refuse any development-only Compose setting",
            (".venv/bin/python", "scripts/validate-production-compose"),
        ),
        ("tls", "Bootstrap TLS and CA references", None),
        ("images", "Verify container image digests", None),
        ("sbom", "Verify package SBOM hashes", None),
    )
    install = (
        (
            "python-package",
            "Install the bundled Mirage Python wheel into a dedicated venv",
            (sys.executable, "scripts/install-mirage-package"),
        ),
        ("deploy", "Deploy the Compose control plane", ("docker", "compose", "--env-file", ".env", "-f", "infra/compose/docker-compose.production.yml", "up", "-d")),
        ("migrations", "Apply PostgreSQL migrations", (".venv/bin/python", "scripts/migrate", "up")),
        ("nats", "Create NATS streams", (".venv/bin/python", "scripts/provision-nats-streams")),
        ("elastic", "Create Elastic templates and data streams", (".venv/bin/python", "scripts/provision-elastic-templates")),
        ("keycloak", "Create Keycloak realm and roles", (".venv/bin/python", "scripts/bootstrap-keycloak-realm")),
        ("step-ca", "Create step-ca provisioners", (".venv/bin/python", "scripts/bootstrap-step-ca-provisioners")),
        ("administrator", "Create initial administrator using protected input", None),
        ("enrolment", "Create one-time agent enrolment token", None),
        ("health", "Verify deployment health", (".venv/bin/python", "scripts/mirage-health")),
        ("synthetic", "Run synthetic transaction", None),
        ("report", "Generate signed installation report", (".venv/bin/python", "scripts/generate-install-report")),
    )
    operation_specific: dict[str, tuple[tuple[str, str, tuple[str, ...] | None], ...]] = {
        "validate": (),
        "status": (("health", "Report installed service status", ("docker", "compose", "--env-file", ".env", "-f", "infra/compose/docker-compose.production.yml", "ps")),),
        "install": install,
        "repair": install[6:],  # skip python-package/deploy/migrations/nats/elastic/keycloak, resume at step-ca
        "upgrade": (
            ("release-verify", "Verify new release package", (".venv/bin/python", "scripts/verify-release")),
            *install,
        ),
        "rollback": (
            ("rollback", "Restore the recorded prior release", (".venv/bin/python", "scripts/rollback-server", "--execute-internal")),
            ("health", "Verify rolled-back service health", (".venv/bin/python", "scripts/mirage-health")),
        ),
        "uninstall": (
            ("uninstall", "Remove services while preserving configured evidence", ("docker", "compose", "--env-file", ".env", "-f", "infra/compose/docker-compose.production.yml", "down"),),
            ("inventory", "Verify service removal and evidence preservation", (".venv/bin/python", "scripts/inventory-aws", "--local-only")),
        ),
    }
    raw = (*common, *operation_specific[operation])
    return tuple(
        InstallStep(
            number=index,
            step_id=value[0],
            description=value[1],
            command=value[2],
            destructive=operation in {"rollback", "uninstall"} and value[0] in {"rollback", "uninstall"},
        )
        for index, value in enumerate(raw, 1)
    )


class ServerInstaller:
    def __init__(
        self,
        *,
        root: Path,
        environment: str,
        config: Path,
        journal: Path,
        package: Path | None = None,
        trusted_public_key: Path | None = None,
        trust_store_dir: Path | None = None,
    ) -> None:
        if not environment or any(character not in "abcdefghijklmnopqrstuvwxyz0123456789-" for character in environment):
            raise ValueError("environment must be a lower-case slug")
        self.root = root.resolve()
        self.environment = environment
        self.config = config.resolve()
        self.journal = journal.resolve()
        self.package = package.resolve() if package else None
        # Trust anchor for release verification. Both default to None, which
        # makes verify_release fall back to the installed trust store and, if
        # that is empty too, fail closed rather than trust the package itself.
        self.trusted_public_key = trusted_public_key.resolve() if trusted_public_key else None
        self.trust_store_dir = trust_store_dir.resolve() if trust_store_dir else None
        if not self.config.is_relative_to(self.root):
            raise ValueError("configuration must be inside the Mirage installation root")

    def preflight(self) -> list[str]:
        errors: list[str] = []
        if platform.system() != "Linux":
            errors.append("server installation requires Ubuntu Linux")
        else:
            os_release = _read_os_release()
            if os_release.get("ID") != "ubuntu":
                errors.append(
                    f"server installation requires Ubuntu, found {os_release.get('ID', 'unknown')}"
                )
            version = os_release.get("VERSION_ID", "").strip('"')
            if version and version not in {"22.04", "24.04"}:
                errors.append(f"unsupported Ubuntu version: {version}")
        if platform.machine() not in {"x86_64", "aarch64"}:
            errors.append(f"unsupported architecture: {platform.machine()}")
        if shutil.disk_usage(self.root).free < 20 * 1024**3:
            errors.append("at least 20 GiB free disk is required")
        if not self.config.is_file():
            errors.append(f"configuration does not exist: {self.config}")
        try:
            socket.getaddrinfo("localhost", None)
        except socket.gaierror:
            errors.append("local DNS resolution failed")
        if self.package is not None and not self.package.is_file():
            errors.append(f"air-gapped release package does not exist: {self.package}")
        return errors

    def run(
        self,
        operation: Operation,
        *,
        dry_run: bool,
        confirmation: str | None = None,
    ) -> dict:
        if operation in {"rollback", "uninstall"}:
            expected = f"mirage:{self.environment}"
            if not dry_run and confirmation != expected:
                raise ValueError(f"destructive operation requires --confirm {expected}")
        plan = server_plan(operation)
        if dry_run:
            return {
                "operation": operation,
                "environment": self.environment,
                "dry_run": True,
                "steps": [asdict(step) for step in plan],
            }
        preflight_errors = self.preflight()
        if preflight_errors:
            raise RuntimeError("; ".join(preflight_errors))
        self._operation = operation
        previous = self._read_journal()
        completed = {
            item["step_id"] for item in previous.get("results", []) if item["status"] == "PASS"
        }
        results: list[dict] = list(previous.get("results", []))
        for step in plan:
            if step.step_id in completed:
                continue
            started = _now()
            try:
                detail = self._execute(step)
                status = "PASS"
            except Exception as exc:
                status = "FAIL"
                detail = f"{type(exc).__name__}: {exc}"
            result = StepResult(step.step_id, status, started, _now(), detail)
            results.append(asdict(result))
            record = {
                "installer_version": "1.0.0",
                "operation": operation,
                "environment": self.environment,
                "host_fingerprint": _host_fingerprint(),
                "configuration_sha256": _sha256(self.config),
                "package_sha256": _sha256(self.package) if self.package else None,
                "results": results,
                **self._installation_metadata(results),
            }
            self._write_journal(record)
            if status == "FAIL":
                raise RuntimeError(f"installer step {step.step_id} failed: {detail}")
        return self._read_journal()

    def _execute(self, step: InstallStep) -> str:
        if step.step_id == "clock":
            return self._validate_clock()
        if step.step_id == "docker":
            return self._ensure_docker()
        if step.step_id == "compose":
            return self._run_command(["docker", "compose", "version"])
        if step.step_id == "configuration":
            command = [
                sys.executable,
                str(self.root / "scripts" / "validate-config"),
                str(self.config),
            ]
            if self.environment not in {"development", "local", "test"}:
                command.append("--strict")
            return self._run_command(command)
        if step.step_id == "release-verify":
            if self.package is None:
                raise RuntimeError("upgrade requires --package")
            verified = verify_release(self.package)
            if not verified["valid"]:
                raise RuntimeError(f"release verification failed: {verified['errors']}")
            return json.dumps(verified, sort_keys=True)
        if step.step_id == "report":
            signing_key_value = os.environ.get("MIRAGE_INSTALL_REPORT_SIGNING_KEY_FILE")
            if not signing_key_value:
                raise RuntimeError(
                    "MIRAGE_INSTALL_REPORT_SIGNING_KEY_FILE must name a protected "
                    "external RSA signing-key file"
                )
            signing_key = Path(signing_key_value).resolve()
            _require_protected_file(signing_key)
            output = Path(
                os.environ.get(
                    "MIRAGE_INSTALL_REPORT_OUTPUT",
                    str(self.journal.with_name("install-report.zip")),
                )
            ).resolve()
            generated = generate_install_report(
                self.journal,
                output=output,
                signing_key=signing_key,
            )
            return json.dumps(generated, sort_keys=True)
        recipe_names = {
            "tls": "MIRAGE_TLS_BOOTSTRAP_RECIPE",
            "administrator": "MIRAGE_ADMIN_BOOTSTRAP_RECIPE",
            "enrolment": "MIRAGE_ENROLMENT_RECIPE",
            "synthetic": "MIRAGE_SYNTHETIC_RECIPE",
            "rollback": "MIRAGE_ROLLBACK_RECIPE",
        }
        if step.step_id in recipe_names:
            return self._run_protected_recipe(recipe_names[step.step_id])
        if step.step_id == "firewall":
            return self._configure_firewall()
        if step.command is None:
            return self._internal_check(step.step_id)
        command = list(step.command)
        if command[:1] == [".venv/bin/python"]:
            command[0] = sys.executable
        return self._run_command(command)

    def _run_command(self, command: list[str]) -> str:
        environment = {
            "PATH": os.environ.get("PATH", ""),
            "MIRAGE_ENV": self.environment,
            "MIRAGE_CONFIG": str(self.config),
        }
        for name in (
            "MIRAGE_API_TOKEN_FILE",
            "MIRAGE_CLI_USERNAME_FILE",
            "MIRAGE_CLI_PASSWORD_FILE",
        ):
            if value := os.environ.get(name):
                environment[name] = value
        result = subprocess.run(
            command,
            cwd=self.root,
            env=environment,
            capture_output=True,
            text=True,
            timeout=900,
            check=False,
        )
        if result.returncode:
            raise RuntimeError((result.stderr or result.stdout or "command failed")[-2000:])
        return (result.stdout or "command completed")[-2000:]

    def _run_protected_recipe(self, environment_name: str) -> str:
        recipe_value = os.environ.get(environment_name)
        if not recipe_value:
            raise RuntimeError(f"{environment_name} must name a protected JSON argv recipe")
        recipe_path = Path(recipe_value).resolve()
        _require_protected_file(recipe_path)
        value = json.loads(recipe_path.read_text())
        if (
            not isinstance(value, list)
            or not value
            or not all(isinstance(item, str) and item for item in value)
        ):
            raise RuntimeError(f"{environment_name} must contain one non-empty JSON argv array")
        return self._run_command(value)

    def _configure_firewall(self) -> str:
        ports = _required_ports()
        if shutil.which("ufw") is None:
            raise RuntimeError("ufw is required on the supported Ubuntu host")
        details = []
        for port in ports:
            details.append(self._run_command(["ufw", "allow", f"{port}/tcp"]))
        details.append(self._run_command(["ufw", "--force", "enable"]))
        details.append(self._run_command(["ufw", "status", "verbose"]))
        return "\n".join(details)[-2000:]

    def _validate_clock(self) -> str:
        timedatectl = subprocess.run(
            ["timedatectl", "show", "--property=NTPSynchronized", "--value"],
            capture_output=True,
            text=True,
            check=False,
        )
        if timedatectl.returncode == 0 and timedatectl.stdout.strip().lower() == "yes":
            return "system clock reports NTP synchronization"
        chronyc = subprocess.run(
            ["chronyc", "tracking"],
            capture_output=True,
            text=True,
            check=False,
        )
        if chronyc.returncode == 0 and "Leap status     : Normal" in chronyc.stdout:
            return "chrony reports a synchronized clock"
        detail = (timedatectl.stderr or timedatectl.stdout or chronyc.stderr)[-500:]
        raise RuntimeError(f"clock synchronization is not verified: {detail}")

    def _ensure_docker(self) -> str:
        if shutil.which("docker") is not None:
            return self._run_command(["docker", "version"])
        if hasattr(os, "geteuid") and os.geteuid() != 0:
            raise RuntimeError("Docker is absent; rerun the installer as root to install it")
        if shutil.which("apt-get") is None:
            raise RuntimeError("Docker is absent and apt-get is unavailable")
        self._run_command(["apt-get", "update"])
        installed = subprocess.run(
            ["apt-get", "install", "-y", "docker.io", "docker-compose-v2"],
            cwd=self.root,
            env={"PATH": os.environ.get("PATH", "")},
            capture_output=True,
            text=True,
            timeout=900,
            check=False,
        )
        if installed.returncode:
            fallback = self._run_command(
                ["apt-get", "install", "-y", "docker.io", "docker-compose-plugin"]
            )
            return f"{fallback}\n{self._run_command(['docker', 'version'])}"
        return self._run_command(["docker", "version"])

    def _internal_check(self, step_id: str) -> str:
        if step_id == "preflight":
            return "Ubuntu/architecture/configuration/package preflight validated"
        if step_id == "capacity":
            return _validate_capacity(self.root)
        if step_id == "dns":
            names = [
                name.strip()
                for name in os.environ.get("MIRAGE_REQUIRED_DNS_NAMES", "localhost").split(",")
                if name.strip()
            ]
            for name in names:
                socket.getaddrinfo(name, None)
            return f"DNS resolved: {', '.join(names)}"
        if step_id == "ports":
            if getattr(self, "_operation", "install") not in {"install", "validate"}:
                return "required-port collision check skipped for installed-service operation"
            checked = []
            for port in _required_ports():
                checked.append(f"{port} ({_probe_port_available(port)})")
            return f"required TCP ports available: {', '.join(checked)}"
        if step_id == "directories":
            created = []
            for path_value in (
                os.environ.get("MIRAGE_STATE_DIRECTORY", "/var/lib/mirage"),
                os.environ.get("MIRAGE_LOG_DIRECTORY", "/var/log/mirage"),
            ):
                path = Path(path_value)
                path.mkdir(mode=0o750, parents=True, exist_ok=True)
                path.chmod(0o750)
                created.append(str(path))
            return f"protected directories ready: {', '.join(created)}"
        if step_id == "secret-references":
            return _validate_secret_references(self.config, self.environment)
        if step_id in {"images", "sbom"}:
            return self._verify_release_inventory(step_id)
        return "internal validation complete"

    def _verify_release_inventory(self, kind: str) -> str:
        if self.package is None:
            raise RuntimeError(f"{kind} verification requires --package")
        # The trust anchor is passed in explicitly and is never taken from the
        # package: verify_release refuses an embedded key on its own, so
        # calling it with neither a public key nor a trust store fails closed
        # ("no external trust anchor configured"). Callers that have no
        # installed trust store — CI, which signs with a key it generated for
        # that run alone — supply the public half via --trusted-public-key.
        verified = verify_release(
            self.package,
            public_key=getattr(self, "trusted_public_key", None),
            trust_store_dir=getattr(self, "trust_store_dir", None),
        )
        if not verified["valid"]:
            raise RuntimeError(f"release verification failed: {verified['errors']}")
        with zipfile.ZipFile(self.package) as archive:
            manifest = json.loads(archive.read("release-manifest.json"))
            if kind == "images":
                value = json.loads(archive.read("container-image-digests.json"))
                images = value.get("images")
                if not isinstance(images, list):
                    raise RuntimeError("container image digest inventory is invalid")
                if self.environment not in {"development", "local", "test"} and not images:
                    raise RuntimeError("production release has no pinned container image digests")
                for image in images:
                    digest = image.get("digest") if isinstance(image, dict) else None
                    if not isinstance(digest, str) or not digest.startswith("sha256:"):
                        raise RuntimeError("container image entry lacks a sha256 digest")
                return f"verified {len(images)} pinned container image digests"
            sboms = [
                name for name in manifest.get("files", {}) if name.startswith("sbom/")
            ]
            if not sboms:
                raise RuntimeError("release contains no SBOM")
            return f"verified signed SBOM members: {', '.join(sorted(sboms))}"

    def _installation_metadata(self, results: list[dict]) -> dict:
        release_metadata = _release_metadata(self.package)
        status_by_step = {item["step_id"]: item for item in results}
        return {
            "installed_time": _now(),
            "container_image_digests": release_metadata["container_image_digests"],
            "sbom_hashes": release_metadata["sbom_hashes"],
            "migration_versions": release_metadata["migration_versions"],
            "contract_versions": release_metadata["contract_versions"],
            "service_health": status_by_step.get("health"),
            "synthetic_transaction_result": status_by_step.get("synthetic"),
        }

    def _read_journal(self) -> dict:
        if not self.journal.exists():
            return {}
        return json.loads(self.journal.read_text())

    def _write_journal(self, value: dict) -> None:
        self.journal.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        temporary = self.journal.with_suffix(".tmp")
        temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
        temporary.chmod(0o600)
        temporary.replace(self.journal)


def _probe_port_available(port: int) -> str:
    """Prove nothing is already listening on `port`, without needing the
    privilege to bind it.

    A plain bind() conflates two very different outcomes on Linux: EADDRINUSE
    ("something else owns this port" — a real collision the installer must
    refuse to install over) and EACCES ("this process is not root, so it may
    not bind a port below 1024" — which says nothing at all about whether the
    port is free). The default required port is 443, so any unprivileged
    caller — CI's clean-install preflight, an operator running `validate`
    before `sudo install` — hit EACCES and reported a phantom collision.

    Binding is still the strongest available signal, so it is tried first and
    its EADDRINUSE result is still fatal. Only when the kernel withholds the
    bind for lack of privilege do we fall back to a connect probe, which
    detects a live listener on the port just as reliably and needs no
    privilege at all.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(("0.0.0.0", port))  # noqa: S104 -- collision check must cover every interface
        return "bind"
    except PermissionError:
        pass  # unprivileged process, privileged port — fall through to the connect probe

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.settimeout(1.0)
        if probe.connect_ex(("127.0.0.1", port)) == 0:
            raise OSError(
                errno.EADDRINUSE,
                f"required TCP port {port} already has a listener",
            )
    return "connect-probe (unprivileged)"


def _required_ports() -> tuple[int, ...]:
    raw = os.environ.get("MIRAGE_REQUIRED_TCP_PORTS", "443")
    try:
        ports = tuple(sorted({int(value.strip()) for value in raw.split(",") if value.strip()}))
    except ValueError as exc:
        raise RuntimeError("MIRAGE_REQUIRED_TCP_PORTS must be comma-separated integers") from exc
    if not ports or any(port < 1 or port > 65535 for port in ports):
        raise RuntimeError("required TCP ports must be in the range 1..65535")
    return ports


def _read_os_release(path: Path = Path("/etc/os-release")) -> dict[str, str]:
    if not path.is_file():
        return {}
    result: dict[str, str] = {}
    for line in path.read_text().splitlines():
        if "=" not in line or line.lstrip().startswith("#"):
            continue
        key, value = line.split("=", 1)
        result[key] = value.strip().strip('"')
    return result


def _validate_capacity(root: Path) -> str:
    cpu_count = os.cpu_count() or 0
    if cpu_count < 2:
        raise RuntimeError("at least two CPU cores are required")
    page_size = os.sysconf("SC_PAGE_SIZE")
    physical_pages = os.sysconf("SC_PHYS_PAGES")
    memory_bytes = page_size * physical_pages
    if memory_bytes < 4 * 1024**3:
        raise RuntimeError("at least 4 GiB RAM is required")
    free_bytes = shutil.disk_usage(root).free
    if free_bytes < 20 * 1024**3:
        raise RuntimeError("at least 20 GiB free disk is required")
    filesystem = subprocess.run(
        ["stat", "-f", "-c", "%T", str(root)],
        capture_output=True,
        text=True,
        check=False,
    )
    filesystem_name = filesystem.stdout.strip() if filesystem.returncode == 0 else "unknown"
    if filesystem_name.lower() in {"nfs", "nfs4", "cifs", "smb2"}:
        raise RuntimeError(f"unsupported installation filesystem: {filesystem_name}")
    return (
        f"capacity validated: cpus={cpu_count}, "
        f"ram_gib={memory_bytes / 1024**3:.1f}, "
        f"free_disk_gib={free_bytes / 1024**3:.1f}, filesystem={filesystem_name}"
    )


def _require_protected_file(path: Path) -> None:
    if not path.is_file():
        raise RuntimeError(f"protected file does not exist: {path}")
    stat_result = path.stat()
    if stat_result.st_mode & 0o077:
        raise RuntimeError(f"protected file must not grant group/other access: {path}")
    if hasattr(os, "getuid") and stat_result.st_uid not in {0, os.getuid()}:
        raise RuntimeError(f"protected file must be owned by root or the installer user: {path}")


def _validate_secret_references(config: Path, environment: str) -> str:
    value = yaml.safe_load(config.read_text())
    if not isinstance(value, dict):
        raise RuntimeError("configuration root must be an object")
    source_fields = (
        ("postgres", "credentials_source"),
        ("nats", "credentials_source"),
        ("elasticsearch", "credentials_source"),
        ("keycloak", "bootstrap_admin_source"),
        ("step_ca", "root_fingerprint_source"),
        ("fleet", "enrollment_token_source"),
    )
    production = environment not in {"development", "local", "test"}
    checked = []
    for section, field in source_fields:
        section_value = value.get(section)
        if not isinstance(section_value, dict):
            raise RuntimeError(f"configuration section is missing: {section}")
        source = section_value.get(field)
        if production and source != "secrets_manager":
            raise RuntimeError(f"{section}.{field} must use secrets_manager")
        if source == "secrets_manager":
            secret_name = section_value.get("secret_name")
            expected_prefix = f"mirage/{environment}/"
            if not isinstance(secret_name, str) or not secret_name.startswith(expected_prefix):
                raise RuntimeError(
                    f"{section}.secret_name must start with {expected_prefix!r}"
                )
        checked.append(f"{section}.{field}={source}")
    return "secret references validated without resolving values: " + ", ".join(checked)


def _release_metadata(package: Path | None) -> dict[str, Any]:
    empty: dict[str, Any] = {
        "container_image_digests": [],
        "sbom_hashes": {},
        "migration_versions": [],
        "contract_versions": [],
    }
    if package is None:
        return empty
    try:
        with zipfile.ZipFile(package) as archive:
            manifest = json.loads(archive.read("release-manifest.json"))
            files = manifest.get("files", {})
            image_inventory = json.loads(archive.read("container-image-digests.json"))
            migration_inventory = json.loads(archive.read("manifests/migrations.json"))
            contract_inventory = json.loads(archive.read("manifests/contracts.json"))
    except (KeyError, json.JSONDecodeError, zipfile.BadZipFile) as exc:
        raise RuntimeError(f"release inventory cannot be read: {exc}") from exc
    return {
        "container_image_digests": image_inventory.get("images", []),
        "sbom_hashes": {
            name: detail.get("sha256")
            for name, detail in files.items()
            if name.startswith("sbom/") and isinstance(detail, dict)
        },
        "migration_versions": [
            item.get("path")
            for item in migration_inventory.get("files", [])
            if isinstance(item, dict)
        ],
        "contract_versions": [
            item.get("path")
            for item in contract_inventory.get("files", [])
            if isinstance(item, dict)
        ],
    }


def cli(default_operation: str | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "operation",
        nargs="?" if default_operation else None,
        default=default_operation,
        choices=SUPPORTED_OPERATIONS,
    )
    parser.add_argument("--environment", required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--package", type=Path)
    parser.add_argument(
        "--trusted-public-key",
        type=Path,
        help="externally trusted signer public key PEM used to verify --package; "
        "overrides the trust store. The package's own embedded key is never trusted.",
    )
    parser.add_argument(
        "--trust-store",
        type=Path,
        help="directory of trusted public keys (default: $MIRAGE_TRUST_STORE_DIR or "
        "/etc/mirage/trust/release-keys)",
    )
    parser.add_argument("--journal", type=Path, default=Path("var/install-journal.json"))
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument(
        "--preflight-only",
        action="store_true",
        help="run non-mutating Ubuntu/package/configuration checks and exit",
    )
    parser.add_argument("--confirm")
    parser.add_argument("--execute-internal", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    installer = ServerInstaller(
        root=Path.cwd(),
        environment=args.environment,
        config=args.config,
        journal=args.journal,
        package=args.package,
        trusted_public_key=args.trusted_public_key,
        trust_store_dir=args.trust_store,
    )
    if args.preflight_only:
        errors = installer.preflight()
        if errors:
            print(json.dumps({"result": "FAIL", "errors": errors}, indent=2))
            return 1
        installer._operation = "validate"
        checks: dict[str, str] = {}
        try:
            for step_id in ("capacity", "dns", "ports", "secret-references"):
                checks[step_id] = installer._internal_check(step_id)
            checks["configuration"] = installer._execute(
                InstallStep(10, "configuration", "Validate configuration", None)
            )
            checks["docker"] = installer._run_command(["docker", "version"])
            checks["compose"] = installer._run_command(["docker", "compose", "version"])
            checks["images"] = installer._verify_release_inventory("images")
            checks["sbom"] = installer._verify_release_inventory("sbom")
        except Exception as exc:
            print(
                json.dumps(
                    {
                        "result": "FAIL",
                        "checks": checks,
                        "error": f"{type(exc).__name__}: {exc}",
                    },
                    indent=2,
                    sort_keys=True,
                )
            )
            return 1
        print(json.dumps({"result": "PASS", "checks": checks}, indent=2, sort_keys=True))
        return 0
    result = installer.run(
        args.operation,
        dry_run=args.dry_run or not args.execute_internal,
        confirmation=args.confirm,
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


def _sha256(path: Path | None) -> str | None:
    if path is None:
        return None
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _host_fingerprint() -> str:
    material = f"{platform.node()}|{platform.machine()}|{platform.platform()}".encode()
    return hashlib.sha256(material).hexdigest()


def _now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")
