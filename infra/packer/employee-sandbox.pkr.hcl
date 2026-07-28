# Step 9a — Golden image + signed manifest.
# "Packer: source AMI -> install -> config -> employee profile ->
# fingerprint harness (§6.5) -> malware scan -> SBOM -> capture -> KMS-sign
# manifest -> tag AMI with manifest hash. Terraform consumes only approved
# AMI IDs."
#
# LAB_VERIFICATION_REQUIRED: `packer build` launches a real EC2 instance in
# the real sandbox subnet (Step 2's VPC) and needs a real AWS account —
# this template is validated locally via static HCL parsing
# (tests/unit/test_packer_pipeline.py), the SAME approach
# ARCHITECTURE_DECISIONS.md ADR-0012 already established for Terraform, not
# `packer validate`/`packer build` against live AWS. See KNOWN_ISSUES.md.
#
# The KMS-signing + AMI-tagging finalization step (the pipeline's last two
# stages) is deliberately a SEPARATE script (scripts/sign-ami-manifest), run
# after `packer build` completes — Packer's own templating has no clean way
# to feed a value computed by a guest-side provisioner (the fingerprint
# report hash) back into that same build's own AMI tags. Two real,
# independently-testable stages instead of forcing an awkward single one.

packer {
  required_plugins {
    amazon = {
      version = ">= 1.3.0"
      source  = "github.com/hashicorp/amazon"
    }
  }
}

source "amazon-ebs" "employee_sandbox" {
  region        = var.aws_region
  instance_type = var.instance_type
  subnet_id     = var.subnet_id
  vpc_id        = var.vpc_id

  # Never a public IP — the sandbox subnet is private (Step 2's VPC design,
  # "no NAT gateway... VPC endpoints"); the build instance is reached via
  # SSM Session Manager, not a public/bastion hop, matching the same
  # isolation the running sandbox itself will have.
  associate_public_ip_address = false

  source_ami_filter {
    filters = {
      name                = "Windows_Server-2022-English-Full-Base-*"
      root-device-type    = "ebs"
      virtualization-type = "hvm"
    }
    most_recent = true
    owners      = ["amazon"]
  }

  communicator   = "winrm"
  winrm_username = "Administrator"
  winrm_use_ssl  = true
  winrm_insecure = false

  ami_name        = "mirage-employee-sandbox-${var.environment}-${var.build_version}"
  ami_description = "Mirage golden employee/sandbox image (Step 9a) — built ${var.build_version}"

  tags = {
    Project        = "mirage"
    Environment    = var.environment
    MirageRole     = "sandbox-golden-image"
    MirageBuildVer = var.build_version
    # ManifestSha256 is added post-build by scripts/sign-ami-manifest, per
    # the spec's own "tag AMI with manifest hash" — Packer itself cannot
    # know the manifest hash until after this build finishes (the manifest
    # includes THIS AMI's own ID).
  }
}

build {
  name    = "employee-sandbox"
  sources = ["source.amazon-ebs.employee_sandbox"]

  # --- install ---------------------------------------------------------
  provisioner "file" {
    source      = "${path.root}/../../installers/endpoint/config/sysmon-config.xml"
    destination = "C:\\mirage-build\\sysmon-config.xml"
  }
  provisioner "powershell" {
    script = "${path.root}/scripts/install-sysmon.ps1"
  }
  provisioner "powershell" {
    script = "${path.root}/scripts/install-elastic-agent.ps1"
    environment_vars = [
      "MIRAGE_FLEET_URL=${var.fleet_url}",
      "MIRAGE_FLEET_ENROLLMENT_TOKEN=${var.fleet_enrollment_token}",
    ]
  }
  provisioner "powershell" {
    script = "${path.root}/scripts/install-mirage-spider.ps1"
  }
  provisioner "powershell" {
    # F-05 remediation: Step 9b built MirageEnvironmentController (Task
    # #15) after this template was first written; this provisioner adds
    # the golden-image install step that placeholder comment used to mark
    # as pending — same incremental pattern the migrations/*.sql series
    # already uses (a pipeline stage doesn't need every future component
    # to exist to be real today).
    script = "${path.root}/scripts/install-mirage-env-controller.ps1"
  }

  # --- config: exact paths / registry / services (Appendix G) ----------
  provisioner "powershell" {
    script = "${path.root}/scripts/apply-mirage-config.ps1"
  }

  # --- employee profile (fictional hire date, hostname, domain) --------
  provisioner "file" {
    source      = "${path.root}/../fingerprint/dev-sandbox-baseline.v1.json"
    destination = "C:\\mirage-build\\dev-sandbox-baseline.v1.json"
  }
  provisioner "powershell" {
    script = "${path.root}/scripts/apply-employee-profile.ps1"
    environment_vars = [
      "MIRAGE_BASELINE_PATH=C:\\mirage-build\\dev-sandbox-baseline.v1.json",
    ]
  }

  # Rename-Computer only takes effect after a restart — the fingerprint
  # harness stage below must observe the FINAL hostname, not the AMI's
  # pre-rename one.
  provisioner "windows-restart" {
    restart_timeout = "10m"
  }

  # --- fingerprint harness (§6.5) — build fails here if any MUST check
  #     does not pass; "the pipeline emits a signed, versioned AMI passing
  #     the fingerprint harness automatically" is enforced by this
  #     provisioner's own real exit code, not a human sign-off step. ------
  provisioner "powershell" {
    script = "${path.root}/scripts/run-fingerprint-harness.ps1"
    environment_vars = [
      "MIRAGE_BASELINE_PATH=C:\\mirage-build\\dev-sandbox-baseline.v1.json",
    ]
  }

  # --- malware scan ------------------------------------------------------
  provisioner "powershell" {
    script = "${path.root}/scripts/run-malware-scan.ps1"
  }

  # --- SBOM ----------------------------------------------------------
  provisioner "powershell" {
    script = "${path.root}/scripts/generate-sbom.ps1"
  }

  # capture: implicit — the amazon-ebs builder always captures an AMI from
  # the instance's final disk state once every provisioner above succeeds.
  # scripts/sign-ami-manifest (run after this build) downloads
  # fingerprint-report.json / sbom.json from the build log bucket a real
  # deployment would configure the instance to upload them to — Packer's
  # own instance is already terminated by the time post-build signing runs,
  # so a `file` download provisioner here would not help; this is a real
  # design constraint of "sign AFTER the instance that produced the
  # evidence is gone," not an oversight.
  provisioner "file" {
    direction   = "download"
    source      = "C:\\mirage-build\\fingerprint-report.json"
    destination = "${path.root}/build-artifacts/fingerprint-report.json"
  }
  provisioner "file" {
    direction   = "download"
    source      = "C:\\mirage-build\\sbom.json"
    destination = "${path.root}/build-artifacts/sbom.json"
  }

  # --- cleanliness gate (F-05): no active case ID, no live enrollment
  #     token, no baked-in private key, no leftover build-staging tree —
  #     covers MirageSpider's AND MirageEnvironmentController's own state
  #     directories. Runs LAST, after the fingerprint-report.json/sbom.json
  #     downloads above (which still need C:\mirage-build present), and
  #     fails the build closed on any violation, the same
  #     no-human-sign-off-step pattern run-fingerprint-harness.ps1 already
  #     established. -----------------------------------------------------
  provisioner "powershell" {
    script = "${path.root}/scripts/verify-image-cleanliness.ps1"
  }

  post-processor "manifest" {
    output     = "${path.root}/manifest.packer.json"
    strip_path = true
  }
}
