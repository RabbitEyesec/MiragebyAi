"""Static policy tests for infra/terraform/modules/evidence's KMS key
policies and bucket hardening (Priority 6 / F-04 remediation: "no
aws_kms_key resource exists... evidence module has S3 but no signing
key" — since resolved, this file locks in that the keys carry a
restrictive, least-privilege policy rather than the AWS-default
account-root-only policy). Same offline HCL-parsing/text-assertion
approach as tests/unit/test_terraform_network_policy.py (ADR-0012).
"""
from __future__ import annotations

from pathlib import Path

import hcl2
import pytest

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[2]
EVIDENCE_MODULE_DIR = REPO_ROOT / "infra" / "terraform" / "modules" / "evidence"
IAM_MODULE_DIR = REPO_ROOT / "infra" / "terraform" / "modules" / "iam"


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
def evidence_resources() -> list[tuple[str, str, dict]]:
    return _load_module_resources(EVIDENCE_MODULE_DIR)


@pytest.fixture(scope="module")
def evidence_main_text() -> str:
    return (EVIDENCE_MODULE_DIR / "main.tf").read_text()


# ---------------------------------------------------------------------------
# Evidence bucket versioning + Object Lock (WORM) — the F-04 fix line names
# these explicitly as required static checks.
# ---------------------------------------------------------------------------

def test_evidence_bucket_versioning_is_enabled(evidence_resources):
    versioning = next(
        attrs for rtype, name, attrs in evidence_resources
        if rtype == "aws_s3_bucket_versioning" and name == "evidence"
    )
    config = versioning["versioning_configuration"]
    block = config[0] if isinstance(config, list) else config
    assert _unquote(block["status"]) == "Enabled"


def test_evidence_bucket_object_lock_enabled_at_creation(evidence_resources):
    bucket = next(
        attrs for rtype, name, attrs in evidence_resources
        if rtype == "aws_s3_bucket" and name == "evidence"
    )
    assert bucket.get("object_lock_enabled") is True


def test_evidence_bucket_object_lock_uses_compliance_mode(evidence_resources):
    lock_config = next(
        attrs for rtype, name, attrs in evidence_resources
        if rtype == "aws_s3_bucket_object_lock_configuration" and name == "evidence"
    )
    rule = lock_config["rule"]
    rule_block = rule[0] if isinstance(rule, list) else rule
    retention = rule_block["default_retention"]
    retention_block = retention[0] if isinstance(retention, list) else retention
    assert _unquote(retention_block["mode"]) == "COMPLIANCE"


def test_evidence_bucket_blocks_all_public_access(evidence_resources):
    block = next(
        attrs for rtype, name, attrs in evidence_resources
        if rtype == "aws_s3_bucket_public_access_block" and name == "evidence"
    )
    for key in ("block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets"):
        assert block.get(key) is True, f"evidence bucket public-access-block.{key} must be true"


# ---------------------------------------------------------------------------
# KMS key policy scope — both keys must carry an explicit `policy` (not rely
# on the AWS-default full-account-root policy alone), and any scoped-usage
# statement must grant only the specific actions a signer/decrypter needs,
# never a wildcard "kms:*" to an arbitrary principal.
# ---------------------------------------------------------------------------

def test_both_kms_keys_have_an_explicit_policy_attribute(evidence_resources):
    for name in ("signing", "evidence_encryption"):
        key = next(attrs for rtype, n, attrs in evidence_resources if rtype == "aws_kms_key" and n == name)
        assert "policy" in key, f"aws_kms_key.{name} has no explicit policy — falls back to the AWS default"


def _statement_window(text: str, sid_marker: str, window: int = 300) -> str:
    """A bounded slice of text starting right after a `sid = "..."` line,
    short enough to cover only that one statement's actions/resources/
    principals block and not spill into a neighboring statement/data block."""
    idx = text.index(sid_marker)
    block = text[idx : idx + window]
    assert "EnableRootAccountManagement" not in block, "window overran into the next statement — narrow it"
    return block


def test_signing_key_scoped_statement_grants_only_sign_actions_not_kms_star(evidence_main_text):
    scoped_block = _statement_window(evidence_main_text, 'sid       = "AllowScopedSigningUsage"')
    assert "kms:Sign" in scoped_block
    assert "kms:GetPublicKey" in scoped_block
    assert '"kms:*"' not in scoped_block


def test_encryption_key_scoped_statement_grants_only_decrypt_actions_not_kms_star(evidence_main_text):
    scoped_block = _statement_window(evidence_main_text, 'sid       = "AllowScopedEncryptDecryptUsage"')
    assert "kms:Decrypt" in scoped_block
    assert "kms:GenerateDataKey" in scoped_block
    assert '"kms:*"' not in scoped_block


def test_kms_key_policies_are_gated_on_caller_supplied_principals_not_hardcoded(evidence_main_text):
    """The scoped statements must only activate when the caller actually
    supplies authorized principal ARNs (dynamic block for_each), so an
    environment that forgets to set them gets root-only access rather than
    a silently-broad default."""
    assert "var.signing_key_authorized_principal_arns" in evidence_main_text
    assert "var.encryption_key_authorized_principal_arns" in evidence_main_text
    assert "for_each = length(var.signing_key_authorized_principal_arns) > 0 ? [1] : []" in evidence_main_text
    assert "for_each = length(var.encryption_key_authorized_principal_arns) > 0 ? [1] : []" in evidence_main_text


def test_root_account_statement_present_on_both_key_policies(evidence_main_text):
    """AWS makes a key unmanageable if its policy omits an IAM-manageable
    root/account statement entirely — this must stay present even though
    actual key USAGE is separately scoped down above."""
    assert evidence_main_text.count('sid       = "EnableRootAccountManagement"') == 2


# ---------------------------------------------------------------------------
# environments/*/main.tf wire a real ARN (not module.iam.*, to avoid the
# iam<->evidence cycle) into these variables — lock in that convention.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("env", ["dev", "acceptance"])
def test_environment_wires_control_node_role_arn_into_evidence_kms_policy(env):
    main_tf = (REPO_ROOT / "infra" / "terraform" / "environments" / env / "main.tf").read_text()
    assert "signing_key_authorized_principal_arns" in main_tf
    assert "encryption_key_authorized_principal_arns" in main_tf
    assert "role/mirage-${var.environment}-control-node" in main_tf
    # Must be a plain ARN string, never a module.iam.* attribute reference
    # (that would create an iam<->evidence circular module dependency).
    # Comment lines are stripped first so prose mentioning "module.iam.*"
    # (explaining exactly why it's avoided) doesn't false-positive the check.
    evidence_block_lines = main_tf.split('module "evidence"')[1].split('module "canary"')[0].splitlines()
    code_only = "\n".join(line for line in evidence_block_lines if not line.strip().startswith("#"))
    assert "module.iam." not in code_only


# ---------------------------------------------------------------------------
# IAM least privilege (module.iam) — sandbox_gateway/agent_ingestion policies
# must never grant the AI-provider or installer-signing secrets, matching
# docs/runbooks/secrets.md's "never exposed to" rules referenced in the
# module's own variable description.
# ---------------------------------------------------------------------------

def test_iam_sandbox_gateway_and_agent_ingestion_never_reference_ai_provider_secret():
    text = (IAM_MODULE_DIR / "main.tf").read_text()
    for policy_name in ("mirage_sandbox_gateway", "mirage_agent_ingestion"):
        block = text.split(f'data "aws_iam_policy_document" "{policy_name}"')[1].split("data \"aws_iam_policy_document\"")[0]
        assert "ai-provider" not in block, f"{policy_name} must never be granted the ai-provider secret"


def test_endpoint_and_sandbox_ec2_instances_get_no_iam_role():
    """ADR-0011's own consequence line: 'Endpoint and sandbox EC2 instances
    get NO instance profile at all — they authenticate via step-ca mTLS
    only.' The iam module itself must declare no aws_iam_instance_profile
    besides the single control_node one."""
    resources = _load_module_resources(IAM_MODULE_DIR)
    profiles = [name for rtype, name, _ in resources if rtype == "aws_iam_instance_profile"]
    assert profiles == ["control_node"]
