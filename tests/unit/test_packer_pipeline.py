"""Static HCL tests for infra/packer/employee-sandbox.pkr.hcl (Step 9a).

Parses the raw HCL source (via python-hcl2) and asserts the exact pipeline
invariants Step 9a requires — provisioner stage order, no public IP,
required tags, sensitive-variable handling — directly against the source
template. No AWS account, no `packer validate`/`packer build`, fully
offline. Mirrors tests/unit/test_terraform_network_policy.py's approach,
which ARCHITECTURE_DECISIONS.md ADR-0012 already established for
Terraform; employee-sandbox.pkr.hcl's own header comment promises this
exact test file.
"""
from __future__ import annotations

import re
from pathlib import Path

import hcl2
import pytest

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[2]
PACKER_DIR = REPO_ROOT / "infra" / "packer"
TEMPLATE_PATH = PACKER_DIR / "employee-sandbox.pkr.hcl"
VARIABLES_PATH = PACKER_DIR / "variables.pkr.hcl"


def _unquote(s: object) -> str:
    s = str(s)
    return s[1:-1] if len(s) >= 2 and s[0] == '"' and s[-1] == '"' else s


@pytest.fixture(scope="module")
def template() -> dict:
    with open(TEMPLATE_PATH) as fh:
        return hcl2.load(fh)


@pytest.fixture(scope="module")
def variables() -> dict:
    with open(VARIABLES_PATH) as fh:
        return hcl2.load(fh)


@pytest.fixture(scope="module")
def source_block(template: dict) -> dict:
    # source block is {"\"amazon-ebs\"": {"\"employee_sandbox\"": {attrs}}}
    outer = template["source"][0]
    inner = next(iter(outer.values()))
    return next(iter(inner.values()))


@pytest.fixture(scope="module")
def build_block(template: dict) -> dict:
    return template["build"][0]


@pytest.fixture(scope="module")
def provisioners(build_block: dict) -> list[tuple[str, dict]]:
    """Returns [(provisioner_type, attrs), ...] in template order."""
    out: list[tuple[str, dict]] = []
    for entry in build_block["provisioner"]:
        (raw_type, attrs), = entry.items()
        out.append((_unquote(raw_type), attrs))
    return out


# ---------------------------------------------------------------------------
# source block: never a public IP, WinRM over TLS
# ---------------------------------------------------------------------------

def test_build_instance_never_gets_a_public_ip(source_block):
    assert source_block["associate_public_ip_address"] is False


def test_build_instance_launches_in_the_sandbox_subnet_variables(source_block):
    assert source_block["subnet_id"] == "${var.subnet_id}"
    assert source_block["vpc_id"] == "${var.vpc_id}"


def test_communicator_is_winrm_over_tls(source_block):
    assert _unquote(source_block["communicator"]) == "winrm"
    assert source_block["winrm_use_ssl"] is True
    assert source_block["winrm_insecure"] is False


def test_ami_tags_include_required_keys(source_block):
    tags = source_block["tags"]
    assert _unquote(tags["Project"]) == "mirage"
    assert tags["Environment"] == "${var.environment}"
    assert _unquote(tags["MirageRole"]) == "sandbox-golden-image"
    assert tags["MirageBuildVer"] == "${var.build_version}"


def test_source_ami_filter_targets_windows_server_2022(source_block):
    filt = source_block["source_ami_filter"][0]["filters"]
    assert "Windows_Server-2022" in _unquote(filt["name"])
    assert _unquote(filt["root-device-type"]) == "ebs"


def test_amazon_plugin_required(template):
    plugins = template["packer"][0]["required_plugins"][0]
    assert "amazon" in plugins
    assert "github.com/hashicorp/amazon" in plugins["amazon"]["source"]


# ---------------------------------------------------------------------------
# provisioner stage order — "source AMI -> install -> config -> employee
# profile -> fingerprint harness (§6.5) -> malware scan -> SBOM -> capture"
# ---------------------------------------------------------------------------

def _script_name(attrs: dict) -> str | None:
    script = attrs.get("script")
    return Path(_unquote(script)).name if script else None


def test_provisioner_stage_order_matches_spec_pipeline(provisioners):
    script_sequence = [_script_name(attrs) for ptype, attrs in provisioners if ptype == "powershell"]
    assert script_sequence == [
        "install-sysmon.ps1",
        "install-elastic-agent.ps1",
        "install-mirage-spider.ps1",
        "install-mirage-env-controller.ps1",
        "apply-mirage-config.ps1",
        "apply-employee-profile.ps1",
        "run-fingerprint-harness.ps1",
        "run-malware-scan.ps1",
        "generate-sbom.ps1",
        "verify-image-cleanliness.ps1",
    ]


def test_env_controller_installed_immediately_after_spider(provisioners):
    """F-05: MirageEnvironmentController's install step belongs in the same
    'install' stage as Spider's, not scattered elsewhere in the pipeline."""
    spider_idx = next(i for i, (t, a) in enumerate(provisioners) if t == "powershell" and _script_name(a) == "install-mirage-spider.ps1")
    controller_idx = next(i for i, (t, a) in enumerate(provisioners) if t == "powershell" and _script_name(a) == "install-mirage-env-controller.ps1")
    assert controller_idx == spider_idx + 1


def test_cleanliness_gate_runs_after_the_artifact_downloads_and_last_overall(provisioners):
    """verify-image-cleanliness.ps1 actively removes C:\\mirage-build — it
    must run strictly after the fingerprint-report.json/sbom.json `file`
    downloads (which still need that directory present), and must be the
    very last provisioner before the manifest post-processor."""
    download_indices = [i for i, (t, a) in enumerate(provisioners) if t == "file" and a.get("direction")]
    cleanliness_idx = next(i for i, (t, a) in enumerate(provisioners) if t == "powershell" and _script_name(a) == "verify-image-cleanliness.ps1")
    assert download_indices, "expected at least one file download provisioner"
    assert cleanliness_idx > max(download_indices)
    assert cleanliness_idx == len(provisioners) - 1, "cleanliness gate must be the last provisioner"


def test_windows_restart_occurs_between_employee_profile_and_fingerprint_harness(provisioners):
    profile_idx = next(i for i, (t, a) in enumerate(provisioners) if t == "powershell" and _script_name(a) == "apply-employee-profile.ps1")
    restart_idx = next(i for i, (t, _) in enumerate(provisioners) if t == "windows-restart")
    harness_idx = next(i for i, (t, a) in enumerate(provisioners) if t == "powershell" and _script_name(a) == "run-fingerprint-harness.ps1")
    assert profile_idx < restart_idx < harness_idx, (
        "hostname rename only takes effect after windows-restart — the fingerprint harness "
        "must observe the FINAL hostname, so restart must sit strictly between profile and harness"
    )


def test_fingerprint_harness_gates_malware_scan_and_sbom(provisioners):
    """§6.5: 'an inconsistent sandbox is worse than none' — the fingerprint
    harness (which aborts the build on failure) must run BEFORE the later,
    slower stages, so a failing image never wastes time on malware scan/SBOM."""
    harness_idx = next(i for i, (t, a) in enumerate(provisioners) if t == "powershell" and _script_name(a) == "run-fingerprint-harness.ps1")
    scan_idx = next(i for i, (t, a) in enumerate(provisioners) if t == "powershell" and _script_name(a) == "run-malware-scan.ps1")
    sbom_idx = next(i for i, (t, a) in enumerate(provisioners) if t == "powershell" and _script_name(a) == "generate-sbom.ps1")
    assert harness_idx < scan_idx < sbom_idx


def test_baseline_file_uploaded_before_fingerprint_harness_runs(provisioners):
    file_uploads = [attrs for ptype, attrs in provisioners if ptype == "file" and attrs.get("destination") and "dev-sandbox-baseline" in attrs["destination"]]
    assert len(file_uploads) == 1
    upload_idx = next(i for i, (t, a) in enumerate(provisioners) if t == "file" and a is file_uploads[0])
    harness_idx = next(i for i, (t, a) in enumerate(provisioners) if t == "powershell" and _script_name(a) == "run-fingerprint-harness.ps1")
    assert upload_idx < harness_idx


def test_fingerprint_and_sbom_artifacts_downloaded_after_being_produced(provisioners):
    downloads = [attrs for ptype, attrs in provisioners if ptype == "file" and attrs.get("direction") and _unquote(attrs["direction"]) == "download"]
    destinations = {Path(_unquote(a["destination"])).name for a in downloads}
    assert destinations == {"fingerprint-report.json", "sbom.json"}
    # generate-sbom.ps1 is the last ARTIFACT-PRODUCING script — it must run
    # before the downloads. verify-image-cleanliness.ps1 is a powershell
    # provisioner too but deliberately runs AFTER the downloads (it deletes
    # C:\mirage-build, which those downloads still need present) — see
    # test_cleanliness_gate_runs_after_the_artifact_downloads_and_last_overall.
    sbom_idx = next(i for i, (t, a) in enumerate(provisioners) if t == "powershell" and _script_name(a) == "generate-sbom.ps1")
    first_download_idx = min(i for i, (t, a) in enumerate(provisioners) if t == "file" and a.get("direction"))
    assert sbom_idx < first_download_idx


def test_manifest_post_processor_declared(build_block):
    post_processors = build_block["post-processor"]
    (raw_type, attrs), = post_processors[0].items()
    assert _unquote(raw_type) == "manifest"
    assert attrs["strip_path"] is True


# ---------------------------------------------------------------------------
# secrets never hardcoded — Fleet enrollment flows through variables only
# ---------------------------------------------------------------------------

def test_elastic_agent_provisioner_uses_variables_not_literal_secrets(provisioners):
    elastic_agent = next(attrs for ptype, attrs in provisioners if ptype == "powershell" and _script_name(attrs) == "install-elastic-agent.ps1")
    env_vars = elastic_agent["environment_vars"]
    joined = " ".join(env_vars)
    assert "${var.fleet_url}" in joined
    assert "${var.fleet_enrollment_token}" in joined


def test_fleet_enrollment_token_variable_is_marked_sensitive(variables):
    var_block = next(v for v in variables["variable"] if _unquote(next(iter(v.keys()))) == "fleet_enrollment_token")
    attrs = next(iter(var_block.values()))
    assert attrs["sensitive"] is True


def test_environment_variable_restricted_to_development_or_acceptance(variables):
    var_block = next(v for v in variables["variable"] if _unquote(next(iter(v.keys()))) == "environment")
    attrs = next(iter(var_block.values()))
    condition = attrs["validation"][0]["condition"]
    assert "development" in condition
    assert "acceptance" in condition


def test_all_required_variables_declared(variables):
    names = {_unquote(next(iter(v.keys()))) for v in variables["variable"]}
    assert names == {
        "environment", "aws_region", "subnet_id", "vpc_id", "instance_type",
        "manifest_kms_key_arn", "build_version", "fleet_url", "fleet_enrollment_token",
    }


# ---------------------------------------------------------------------------
# install-mirage-env-controller.ps1 (F-05) — Appendix G: "never LocalSystem,"
# a dedicated restricted service account, matching config.SERVICE_ACCOUNT /
# config.SERVICE_NAME / actions.APPROVED_DECOY_SERVICES exactly so this
# script and the actual application code can never silently drift apart.
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def env_controller_install_script() -> str:
    return (PACKER_DIR / "scripts" / "install-mirage-env-controller.ps1").read_text()


@pytest.fixture(scope="module")
def controller_config_source() -> str:
    return (REPO_ROOT / "agents" / "mirage-env-controller" / "mirage_env_controller" / "config.py").read_text()


@pytest.fixture(scope="module")
def controller_actions_source() -> str:
    return (REPO_ROOT / "agents" / "mirage-env-controller" / "mirage_env_controller" / "actions.py").read_text()


def test_env_controller_service_account_matches_config_py(env_controller_install_script, controller_config_source):
    # config.py's raw source text contains a doubled backslash (an escaped
    # single backslash in Python syntax) — matched here with a raw string
    # so the two literal backslash characters line up exactly.
    assert r'SERVICE_ACCOUNT = "MirageSandbox\\svc-mirage-envctl"' in controller_config_source
    assert "svc-mirage-envctl" in env_controller_install_script


def test_env_controller_never_runs_as_localsystem_or_localservice(env_controller_install_script):
    script = env_controller_install_script
    assert "LocalSystem" in script  # present only in the guard that rejects it
    assert 'throw "MirageEnvironmentController is running as LocalSystem' in script
    assert "NT AUTHORITY\\LocalService" not in script, "Controller must use its own restricted account, not Spider's LocalService"


def test_env_controller_install_generates_a_fresh_random_password_never_a_literal(env_controller_install_script):
    script = env_controller_install_script
    assert "GeneratePassword" in script
    # No quoted literal password string anywhere (only the generated variable is used).
    assert not re.search(r'password\s*=\s*"[^$][^"]*"', script, re.IGNORECASE)


def test_env_controller_install_copies_mirage_contracts_and_mirage_common(env_controller_install_script):
    script = env_controller_install_script
    assert "mirage_contracts" in script
    assert "mirage_common" in script
    assert "mirage_env_controller" in script


def test_env_controller_decoy_content_root_grants_only_modify_not_full_control(env_controller_install_script):
    script = env_controller_install_script
    assert '"Modify"' in script
    assert "FullControl" not in script


def test_env_controller_approved_decoy_services_match_actions_py(env_controller_install_script, controller_actions_source):
    for service_name in ("MirageDecoyPrintSpooler", "MirageDecoyRemoteRegistry", "MirageDecoyFtp"):
        assert service_name in controller_actions_source
        assert service_name in env_controller_install_script


def test_spider_install_script_also_copies_mirage_contracts():
    """Real gap found while writing the Controller's equivalent copy step:
    service_logic.py imports mirage_contracts.envelope/timestamps directly,
    but the script never copied that package — masked in every environment
    that ran it with this repo's own editable install already on sys.path."""
    script = (PACKER_DIR / "scripts" / "install-mirage-spider.ps1").read_text()
    assert "mirage_contracts" in script


# ---------------------------------------------------------------------------
# verify-image-cleanliness.ps1 (F-05) — the pipeline's final gate.
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def cleanliness_script() -> str:
    return (PACKER_DIR / "scripts" / "verify-image-cleanliness.ps1").read_text()


def test_cleanliness_script_checks_all_four_named_categories(cleanliness_script):
    script = cleanliness_script
    assert "case_id" in script  # no active case ID
    assert "MIRAGE_FLEET_ENROLLMENT_TOKEN" in script  # no live enrollment token
    assert "*.pem" in script and "*.key" in script  # no baked-in private key
    assert "mirage-build" in script  # no leftover build-staging tree


def test_cleanliness_script_covers_both_spider_and_controller_state_dirs(cleanliness_script):
    script = cleanliness_script
    assert "Mirage\\Spider" in script
    assert "Mirage\\EnvController" in script


def test_cleanliness_script_fails_closed_on_any_violation(cleanliness_script):
    assert "$violations.Count -gt 0" in cleanliness_script
    assert "throw " in cleanliness_script
