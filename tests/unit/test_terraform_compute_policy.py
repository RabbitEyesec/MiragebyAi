"""Static policy tests for infra/terraform/modules/compute (Priority 6 /
F-04 remediation: "no aws_instance resource exists anywhere in the module
tree"). Same offline HCL-parsing approach as
tests/unit/test_terraform_network_policy.py (see ARCHITECTURE_DECISIONS.md
ADR-0012) — no AWS account, no `terraform plan`, fully deterministic.
"""
from __future__ import annotations

from pathlib import Path

import hcl2
import pytest

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[2]
COMPUTE_MODULE_DIR = REPO_ROOT / "infra" / "terraform" / "modules" / "compute"

PRIVATE_ROLES = ("control", "endpoint", "sandbox", "attacker")


def _unquote(s: object) -> str:
    s = str(s)
    return s[1:-1] if len(s) >= 2 and s[0] == '"' and s[-1] == '"' else s


def _load_module_resources(module_dir: Path) -> list[tuple[str, str, dict]]:
    out: list[tuple[str, str, dict]] = []
    for tf_file in sorted(module_dir.glob("*.tf")):
        with open(tf_file) as fh:
            data = hcl2.load(fh)
        for block in data.get("resource", []):
            for rtype, instances in block.items():
                rtype = _unquote(rtype)
                for name, attrs in instances.items():
                    out.append((rtype, _unquote(name), attrs))
    return out


@pytest.fixture(scope="module")
def compute_resources() -> list[tuple[str, str, dict]]:
    return _load_module_resources(COMPUTE_MODULE_DIR)


@pytest.fixture(scope="module")
def instances(compute_resources) -> dict[str, dict]:
    return {name: attrs for rtype, name, attrs in compute_resources if rtype == "aws_instance"}


# ---------------------------------------------------------------------------
# "No private instance is configured with a public IP" — same Step 2 rule
# the vpc module's subnets already enforce at the subnet level; this module
# is the first to actually declare instances, so it must enforce it too.
# ---------------------------------------------------------------------------

def test_every_role_has_exactly_one_instance(instances):
    assert set(instances) == {"broker", "control", "endpoint", "sandbox", "attacker"}


def test_only_broker_instance_has_a_public_ip(instances):
    for name, attrs in instances.items():
        expected = name == "broker"
        assert attrs.get("associate_public_ip_address") is expected, (
            f"instance {name}: associate_public_ip_address={attrs.get('associate_public_ip_address')!r}, expected {expected}"
        )


def test_no_elastic_ip_resource_in_compute_module(compute_resources):
    eips = [name for rtype, name, _ in compute_resources if rtype == "aws_eip"]
    assert eips == []


# ---------------------------------------------------------------------------
# ADR-0011: only the control instance gets an IAM instance profile — endpoint/
# sandbox/attacker/broker authenticate via step-ca mTLS or hold no AWS
# identity at all, never an instance-profile-derived credential.
# ---------------------------------------------------------------------------

def test_only_control_instance_has_an_iam_instance_profile(instances):
    for name, attrs in instances.items():
        has_profile = "iam_instance_profile" in attrs
        expected = name == "control"
        assert has_profile is expected, (
            f"instance {name}: iam_instance_profile present={has_profile}, expected {expected}"
        )


# ---------------------------------------------------------------------------
# Baseline hardening that must hold for every instance regardless of role.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("name", ["broker", "control", "endpoint", "sandbox", "attacker"])
def test_every_instance_has_an_encrypted_root_volume(instances, name):
    root_bd = instances[name].get("root_block_device")
    assert root_bd, f"instance {name}: no root_block_device configured"
    block = root_bd[0] if isinstance(root_bd, list) else root_bd
    assert block.get("encrypted") is True, f"instance {name}: root volume not encrypted"


@pytest.mark.parametrize("name", ["broker", "control", "endpoint", "sandbox", "attacker"])
def test_every_instance_enforces_imdsv2(instances, name):
    metadata = instances[name].get("metadata_options")
    assert metadata, f"instance {name}: no metadata_options configured"
    block = metadata[0] if isinstance(metadata, list) else metadata
    assert _unquote(block.get("http_tokens", "")) == "required", f"instance {name}: IMDSv2 not enforced"
    assert block.get("http_put_response_hop_limit") == 1, f"instance {name}: hop limit not restricted to 1"


# The vpc module names its public-facing subnet/security-group
# "public_edge", not "broker" — the compute module's broker instance lives
# there (Step 8b/8c/8d brokers run on the public edge). Every other role
# name matches its subnet/security-group name 1:1.
SUBNET_KEY_BY_ROLE = {
    "broker": "public_edge",
    "control": "control",
    "endpoint": "endpoint",
    "sandbox": "sandbox",
    "attacker": "attacker",
}


@pytest.mark.parametrize("name", ["broker", "control", "endpoint", "sandbox", "attacker"])
def test_every_instance_is_in_its_own_named_subnet(instances, name):
    expected_key = SUBNET_KEY_BY_ROLE[name]
    subnet_ref = str(instances[name].get("subnet_id"))
    assert f"var.subnet_ids.{expected_key}" in subnet_ref, f"instance {name}: wired to wrong subnet {subnet_ref!r}"


@pytest.mark.parametrize("name", ["broker", "control", "endpoint", "sandbox", "attacker"])
def test_every_instance_uses_its_own_security_group_only(instances, name):
    expected_key = SUBNET_KEY_BY_ROLE[name]
    sg_ref = str(instances[name].get("vpc_security_group_ids"))
    assert f"var.security_group_ids.{expected_key}" in sg_ref, f"instance {name}: wired to wrong security group {sg_ref!r}"
    for other_role, other_key in SUBNET_KEY_BY_ROLE.items():
        if other_key == expected_key:
            continue
        assert f"var.security_group_ids.{other_key}" not in sg_ref, (
            f"instance {name}: unexpectedly also references {other_role}'s security group"
        )


# ---------------------------------------------------------------------------
# Tagging (Prompt-1 instructions: "All resources carry Project=mirage and
# Environment=<environment>"), plus a Role tag distinguishing the five roles.
# ---------------------------------------------------------------------------

def test_local_common_tags_includes_project_and_environment():
    text = (COMPUTE_MODULE_DIR / "main.tf").read_text()
    assert 'Project     = "mirage"' in text
    assert "Environment = var.environment" in text


@pytest.mark.parametrize("name", ["broker", "control", "endpoint", "sandbox", "attacker"])
def test_every_instance_has_a_role_tag_matching_its_own_name(instances, name):
    tags_ref = str(instances[name].get("tags"))
    assert f'Role = "{name}"' in tags_ref.replace("'", '"'), f"instance {name}: missing or mismatched Role tag"
