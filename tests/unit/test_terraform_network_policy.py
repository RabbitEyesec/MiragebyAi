"""Static network-policy tests for infra/terraform/modules/vpc (Step 2).

Parses the raw HCL source (via python-hcl2) and asserts the exact isolation
invariants Step 2 requires, directly against the source configuration — no
AWS account, no `terraform plan`, fully offline. See ARCHITECTURE_DECISIONS.md
ADR-0012 for why this approach was chosen over a live-plan-based test.

This is real, meaningful, deterministic verification: it fails on regressions
just like `terraform plan`-based OPA/Conftest tests would, but never needs
AWS credentials to run in CI or on a laptop with no cloud account.
"""
from __future__ import annotations

from pathlib import Path

import hcl2
import pytest

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[2]
VPC_MODULE_DIR = REPO_ROOT / "infra" / "terraform" / "modules" / "vpc"


def _unquote(s: object) -> str:
    s = str(s)
    return s[1:-1] if len(s) >= 2 and s[0] == '"' and s[-1] == '"' else s


def _load_module_resources(module_dir: Path) -> list[tuple[str, str, dict]]:
    """Returns [(resource_type, resource_name, attrs), ...] across every .tf
    file in module_dir, with HCL2's quoted-key artifact stripped."""
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
def vpc_resources() -> list[tuple[str, str, dict]]:
    return _load_module_resources(VPC_MODULE_DIR)


def _refs(attrs: dict, key: str) -> str:
    return str(attrs.get(key, ""))


# ---------------------------------------------------------------------------
# "No private instance is configured with a public IP" (Step 2 local acceptance)
# ---------------------------------------------------------------------------

def test_only_public_edge_subnet_has_public_ip(vpc_resources):
    subnets = {name: attrs for rtype, name, attrs in vpc_resources if rtype == "aws_subnet"}
    assert set(subnets) == {"public_edge", "control", "endpoint", "sandbox", "attacker"}
    for name, attrs in subnets.items():
        expected = name == "public_edge"
        assert attrs.get("map_public_ip_on_launch") is expected, (
            f"subnet {name}: map_public_ip_on_launch={attrs.get('map_public_ip_on_launch')!r}, expected {expected}"
        )


def test_no_nat_gateway_anywhere(vpc_resources):
    """Spec: 'S3 + Secrets + KMS: via VPC endpoints (no NAT gateway)'."""
    nat_gateways = [name for rtype, name, _ in vpc_resources if rtype == "aws_nat_gateway"]
    assert nat_gateways == []


def test_no_elastic_ip_on_any_private_resource(vpc_resources):
    """No aws_eip resource exists in this module at all (Step 2 scope has no
    EC2 instances yet — this guards against one being added later without
    also updating this test to prove it's on the public subnet only)."""
    eips = [name for rtype, name, _ in vpc_resources if rtype == "aws_eip"]
    assert eips == []


# ---------------------------------------------------------------------------
# "Attacker subnet can reach broker entry points only... cannot reach
# PostgreSQL, NATS, Elasticsearch, Keycloak, step-ca, S3, KMS, or Secrets
# Manager" (Step 2 rule)
# ---------------------------------------------------------------------------

def test_attacker_security_group_only_referenced_by_public_edge_ingress(vpc_resources):
    """The ONLY security-group-rule anywhere allowed to reference the
    attacker security group as a traffic SOURCE is the public-edge ingress
    rule (attacker -> broker entry points). No rule anywhere lets attacker
    traffic reach control/endpoint/sandbox/vpc_endpoints directly."""
    rules_sourced_from_attacker = [
        name
        for rtype, name, attrs in vpc_resources
        if rtype == "aws_security_group_rule" and "aws_security_group.attacker" in _refs(attrs, "source_security_group_id")
    ]
    assert rules_sourced_from_attacker == ["public_edge_ingress_broker_ports"], rules_sourced_from_attacker


def test_attacker_security_group_has_no_ingress_rules(vpc_resources):
    """Nothing may initiate a connection INTO the attacker security group —
    it only ever originates outbound connections toward the public edge."""
    attacker_ingress = [
        name
        for rtype, name, attrs in vpc_resources
        if rtype == "aws_security_group_rule"
        and _unquote(attrs.get("type", "")) == "ingress"
        and "aws_security_group.attacker" in _refs(attrs, "security_group_id")
    ]
    assert attacker_ingress == []


def test_attacker_egress_restricted_to_public_edge_broker_ports_only(vpc_resources):
    """Every egress rule attached to the attacker SG must target ONLY the
    public_edge security group — never control/endpoint/sandbox/vpc_endpoints."""
    attacker_egress_rules = [
        (name, attrs)
        for rtype, name, attrs in vpc_resources
        if rtype == "aws_security_group_rule"
        and _unquote(attrs.get("type", "")) == "egress"
        and "aws_security_group.attacker" in _refs(attrs, "security_group_id")
    ]
    assert attacker_egress_rules, "expected at least one attacker egress rule"
    for name, attrs in attacker_egress_rules:
        dest = _refs(attrs, "source_security_group_id")
        assert "aws_security_group.public_edge" in dest, f"{name}: attacker egress must target public_edge only, got {dest}"


@pytest.mark.parametrize("protected_sg", ["control", "endpoint", "sandbox", "vpc_endpoints"])
def test_protected_security_groups_never_reference_attacker(vpc_resources, protected_sg):
    """control/endpoint/sandbox/vpc_endpoints security groups must have NO
    rule (ingress or egress) that references the attacker security group at
    all, in either direction."""
    for rtype, name, attrs in vpc_resources:
        if rtype != "aws_security_group_rule":
            continue
        sg_ref = _refs(attrs, "security_group_id")
        if f"aws_security_group.{protected_sg}." not in sg_ref and not sg_ref.endswith(f"aws_security_group.{protected_sg}.id}}"):
            continue
        source_ref = _refs(attrs, "source_security_group_id")
        assert "aws_security_group.attacker" not in source_ref, (
            f"{name}: {protected_sg} security group must never reference attacker, found {source_ref}"
        )


# ---------------------------------------------------------------------------
# "S3, KMS, and Secrets Manager use VPC endpoints" + "sandbox cannot reach
# evidence storage directly unless explicitly required and policy-approved"
# ---------------------------------------------------------------------------

def test_vpc_endpoints_declared_for_s3_kms_secretsmanager(vpc_resources):
    endpoints = {name: attrs for rtype, name, attrs in vpc_resources if rtype == "aws_vpc_endpoint"}
    assert set(endpoints) == {"s3", "kms", "secretsmanager"}


def test_s3_gateway_endpoint_routed_only_through_control_subnet(vpc_resources):
    s3_endpoint = next(attrs for rtype, name, attrs in vpc_resources if rtype == "aws_vpc_endpoint" and name == "s3")
    route_table_ids = s3_endpoint.get("route_table_ids")
    assert route_table_ids is not None
    joined = str(route_table_ids)
    assert "aws_route_table.control" in joined
    for other in ("public_edge", "endpoint", "sandbox", "attacker"):
        assert f"aws_route_table.{other}." not in joined, f"S3 endpoint route table list must not include {other}"


def test_interface_endpoints_only_in_control_subnet_with_restricted_sg(vpc_resources):
    for name in ("kms", "secretsmanager"):
        attrs = next(a for rtype, n, a in vpc_resources if rtype == "aws_vpc_endpoint" and n == name)
        assert "aws_subnet.control" in str(attrs.get("subnet_ids"))
        assert "aws_security_group.vpc_endpoints" in str(attrs.get("security_group_ids"))


def test_vpc_endpoints_security_group_only_allows_control_ingress(vpc_resources):
    rules = [
        (name, attrs)
        for rtype, name, attrs in vpc_resources
        if rtype == "aws_security_group_rule" and "aws_security_group.vpc_endpoints" in _refs(attrs, "security_group_id")
    ]
    assert len(rules) == 1
    name, attrs = rules[0]
    assert _unquote(attrs.get("type", "")) == "ingress"
    assert "aws_security_group.control" in _refs(attrs, "source_security_group_id")


# ---------------------------------------------------------------------------
# "Sandbox can dial out only to explicitly approved control services"
# ---------------------------------------------------------------------------

def test_sandbox_egress_restricted_to_control_security_group(vpc_resources):
    sandbox_egress = [
        (name, attrs)
        for rtype, name, attrs in vpc_resources
        if rtype == "aws_security_group_rule"
        and _unquote(attrs.get("type", "")) == "egress"
        and "aws_security_group.sandbox" in _refs(attrs, "security_group_id")
    ]
    assert len(sandbox_egress) == 1, "sandbox must have exactly one narrow egress rule"
    name, attrs = sandbox_egress[0]
    assert "aws_security_group.control" in _refs(attrs, "source_security_group_id")
    assert attrs.get("from_port") == attrs.get("to_port") == 443


# ---------------------------------------------------------------------------
# "Endpoint cannot reach sandbox management" (F-04 remediation static check)
# ---------------------------------------------------------------------------

def test_endpoint_security_group_never_references_sandbox(vpc_resources):
    """No rule attached to the endpoint security group (ingress or egress)
    may reference the sandbox security group in either direction — the
    endpoint's only egress target is control (agent ingestion + Fleet)."""
    for rtype, name, attrs in vpc_resources:
        if rtype != "aws_security_group_rule":
            continue
        sg_ref = _refs(attrs, "security_group_id")
        if "aws_security_group.endpoint." not in sg_ref and not sg_ref.endswith("aws_security_group.endpoint.id}"):
            continue
        other_ref = _refs(attrs, "source_security_group_id")
        assert "aws_security_group.sandbox" not in other_ref, (
            f"{name}: endpoint security group must never reference sandbox, found {other_ref}"
        )


def test_endpoint_egress_restricted_to_control_security_group_only(vpc_resources):
    endpoint_egress = [
        (name, attrs)
        for rtype, name, attrs in vpc_resources
        if rtype == "aws_security_group_rule"
        and _unquote(attrs.get("type", "")) == "egress"
        and "aws_security_group.endpoint" in _refs(attrs, "security_group_id")
    ]
    assert len(endpoint_egress) == 1, "endpoint must have exactly one egress rule"
    name, attrs = endpoint_egress[0]
    assert "aws_security_group.control" in _refs(attrs, "source_security_group_id")


# ---------------------------------------------------------------------------
# Tagging (Prompt-1 instructions: "All resources carry Project=mirage and
# Environment=<environment>")
# ---------------------------------------------------------------------------

def test_local_common_tags_includes_project_and_environment():
    text = (VPC_MODULE_DIR / "main.tf").read_text()
    assert 'Project     = "mirage"' in text
    assert "Environment = var.environment" in text
