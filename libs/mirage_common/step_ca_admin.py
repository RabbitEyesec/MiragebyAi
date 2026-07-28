"""Administrative operations against a running step-ca container: add JWK
provisioners by editing ca.json directly and restarting.

Shared by scripts/bootstrap-step-ca-provisioners (persistent dev container)
and tests/integration/conftest.py (ephemeral per-test-module container) so
both exercise the identical real logic — no separate "test-only" reimplementation.
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path


class StepCaAdminError(Exception):
    pass


def _run(cmd: list[str], **kwargs) -> subprocess.CompletedProcess:
    result = subprocess.run(cmd, capture_output=True, text=True, **kwargs)
    if result.returncode != 0:
        raise StepCaAdminError(f"{' '.join(cmd)} failed:\n{result.stdout}\n{result.stderr}")
    return result


def _jwe_json_to_compact(jwe: dict) -> str:
    return ".".join([jwe["protected"], jwe["encrypted_key"], jwe["iv"], jwe["ciphertext"], jwe["tag"]])


@dataclass(frozen=True)
class ProvisionerProfile:
    name: str
    max_hours: int
    min_hours: int
    default_hours: int


DEFAULT_PROFILES: list[ProvisionerProfile] = [
    ProvisionerProfile("mirage-endpoint", 24, 1, 24),
    ProvisionerProfile("mirage-spider", 24, 1, 24),
    ProvisionerProfile("mirage-env-controller", 24, 1, 24),
    ProvisionerProfile("mirage-broker-client", 720, 24, 168),
    ProvisionerProfile("mirage-internal-control", 720, 24, 168),
]


def _generate_provisioner_keypair(name: str, password: str, tmpdir: Path, keys_out_dir: Path | None) -> dict:
    pub_path = tmpdir / f"{name}.pub.json"
    priv_path = tmpdir / f"{name}.priv.json"
    pass_path = tmpdir / f"{name}.pass.txt"
    pass_path.write_text(password)

    _run([
        "step", "crypto", "jwk", "create", str(pub_path), str(priv_path),
        "--password-file", str(pass_path), "--kty", "EC", "--curve", "P-256", "--force",
    ])
    pub = json.loads(pub_path.read_text())
    priv_jwe = json.loads(priv_path.read_text())

    if keys_out_dir is not None:
        keys_out_dir.mkdir(parents=True, exist_ok=True)
        try:
            (keys_out_dir / f"{name}.priv.json").write_text(priv_path.read_text())
            (keys_out_dir / f"{name}.pub.json").write_text(pub_path.read_text())
        except PermissionError as exc:
            # Almost always the compose bind mount: if this directory did not
            # exist when `docker compose up` ran, the root-owned Docker daemon
            # created it and we are not root. `make compose-dirs` (a
            # prerequisite of `make compose-up`) exists to prevent exactly
            # this; say so rather than surfacing a bare errno 13.
            raise StepCaAdminError(
                f"cannot write provisioner keys into {keys_out_dir} ({exc.strerror}). "
                "This directory is bind-mounted by the compose stack; if Docker created "
                "it, it is owned by root. Run `make compose-dirs` before `make compose-up`, "
                f"or reclaim it with: sudo chown -R \"$(id -u):$(id -g)\" {keys_out_dir}"
            ) from exc

    return {"pub": pub, "encrypted_key": _jwe_json_to_compact(priv_jwe)}


def add_provisioners(
    container_name: str,
    *,
    profiles: list[ProvisionerProfile] = DEFAULT_PROFILES,
    password: str = "mirage_dev_local_only",
    keys_out_dir: Path | None = None,
    restart: bool = True,
) -> list[str]:
    """Idempotently add JWK provisioners (skipping any name already present)
    to the step-ca container's ca.json, then restart it to pick up the change.

    Returns the list of provisioner names actually added.
    """
    with tempfile.TemporaryDirectory() as tmp:
        tmpdir = Path(tmp)

        current = _run(["docker", "exec", container_name, "cat", "/home/step/config/ca.json"])
        ca_config = json.loads(current.stdout)
        provisioners = ca_config["authority"]["provisioners"]
        existing_names = {p["name"] for p in provisioners}

        added: list[str] = []
        for profile in profiles:
            if profile.name in existing_names:
                continue
            keys = _generate_provisioner_keypair(profile.name, password, tmpdir, keys_out_dir)
            provisioners.append({
                "type": "JWK",
                "name": profile.name,
                "key": keys["pub"],
                "encryptedKey": keys["encrypted_key"],
                "claims": {
                    "maxTLSCertDuration": f"{profile.max_hours}h",
                    "minTLSCertDuration": f"{profile.min_hours}h",
                    "defaultTLSCertDuration": f"{profile.default_hours}h",
                },
            })
            added.append(profile.name)

        if not added:
            return []

        new_config_path = tmpdir / "ca.json"
        new_config_path.write_text(json.dumps(ca_config, indent=2))
        _run(["docker", "cp", str(new_config_path), f"{container_name}:/home/step/config/ca.json"])
        if restart:
            _run(["docker", "restart", container_name])

    return added


def fetch_root_cert(container_name: str, dest_path: Path) -> None:
    result = _run(["docker", "exec", container_name, "cat", "/home/step/certs/root_ca.crt"])
    dest_path.write_text(result.stdout)


def has_step_cli() -> bool:
    import shutil

    return shutil.which("step") is not None


if __name__ == "__main__":
    print("This module is a library — see scripts/bootstrap-step-ca-provisioners for the CLI.", file=sys.stderr)
    raise SystemExit(1)
