# EC2 compute for the five topology roles (spec §5; Priority 6 remediation
# of Step 2's Prompt-1 scope, which stopped at VPC/IAM/evidence/log modules
# per IMPLEMENTATION_STATUS.md Step 2 — see ARCHITECTURE_DECISIONS.md
# ADR-0011/ADR-0012 for the IAM and static-policy-testing decisions this
# module extends).
#
# One instance per role:
#   broker   — public_edge subnet. Nginx/HTTP broker, SSH bastion, RD
#              Gateway (Step 8b/8c/8d). The ONLY instance in this module
#              with a public IP — matches the vpc module's public_edge
#              subnet, the one subnet meant to be internet-reachable.
#   control  — control subnet. Single Docker-Compose control node running
#              mirage-api/worker/outbox-relay/agent-ingestion/sandbox-gateway
#              (ADR-0011). The ONLY instance with an IAM instance profile.
#   endpoint — endpoint subnet. Windows employee VM (Sysmon, Elastic Agent,
#              MirageEndpoint).
#   sandbox  — sandbox subnet. Windows sandbox VM (Spider, EnvController).
#              Dials out only (vpc module's sandbox security group).
#   attacker — attacker subnet. Kali (or any simulated intruder host).
#
# No private-tier instance (control/endpoint/sandbox/attacker) is ever
# given a public IP, an Elastic IP, or an IAM instance profile beyond
# control's own — see tests/unit/test_terraform_compute_policy.py.

locals {
  common_tags = {
    Project     = "mirage"
    Environment = var.environment
    ManagedBy   = "terraform"
  }

}

# tfsec ignore below: this is the vpc module's public_edge subnet, the one
# instance in the whole topology meant to be internet-reachable (Nginx/SSH
# bastion/RD Gateway entry points — spec §5). Every other instance in this
# module has associate_public_ip_address = false — see
# tests/unit/test_terraform_compute_policy.py.
#tfsec:ignore:aws-ec2-no-public-ip
resource "aws_instance" "broker" {
  ami                    = var.ami_ids.broker
  instance_type          = var.instance_types.broker
  subnet_id              = var.subnet_ids.public_edge
  vpc_security_group_ids = [var.security_group_ids.public_edge]

  associate_public_ip_address = true
  monitoring                  = var.enable_detailed_monitoring
  key_name                    = var.key_name

  root_block_device {
    volume_size = var.root_volume_sizes_gb.broker
    encrypted   = true
  }

  # IMDSv2-only, single-hop — no instance in this module ever allows the
  # legacy IMDSv1 GET-token-optional path (SSRF-to-credential-theft guard).
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required" # secret-scan: ignore (IMDSv2 mode enum, not a secret)
    http_put_response_hop_limit = 1
  }

  tags = merge(local.common_tags, { Name = "mirage-${var.environment}-broker", Role = "broker" })
}

resource "aws_instance" "control" {
  ami                    = var.ami_ids.control
  instance_type          = var.instance_types.control
  subnet_id              = var.subnet_ids.control
  vpc_security_group_ids = [var.security_group_ids.control]
  iam_instance_profile   = var.control_node_instance_profile_name

  associate_public_ip_address = false
  monitoring                  = var.enable_detailed_monitoring
  key_name                    = var.key_name

  root_block_device {
    volume_size = var.root_volume_sizes_gb.control
    encrypted   = true
  }

  # IMDSv2-only, single-hop — no instance in this module ever allows the
  # legacy IMDSv1 GET-token-optional path (SSRF-to-credential-theft guard).
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required" # secret-scan: ignore (IMDSv2 mode enum, not a secret)
    http_put_response_hop_limit = 1
  }

  tags = merge(local.common_tags, { Name = "mirage-${var.environment}-control", Role = "control" })
}

resource "aws_instance" "endpoint" {
  ami                    = var.ami_ids.endpoint
  instance_type          = var.instance_types.endpoint
  subnet_id              = var.subnet_ids.endpoint
  vpc_security_group_ids = [var.security_group_ids.endpoint]

  # No iam_instance_profile — endpoint authenticates exclusively via
  # step-ca mTLS certificates (ADR-0002, ADR-0011), never AWS credentials.
  associate_public_ip_address = false
  monitoring                  = var.enable_detailed_monitoring
  key_name                    = var.key_name

  root_block_device {
    volume_size = var.root_volume_sizes_gb.endpoint
    encrypted   = true
  }

  # IMDSv2-only, single-hop — no instance in this module ever allows the
  # legacy IMDSv1 GET-token-optional path (SSRF-to-credential-theft guard).
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required" # secret-scan: ignore (IMDSv2 mode enum, not a secret)
    http_put_response_hop_limit = 1
  }

  tags = merge(local.common_tags, { Name = "mirage-${var.environment}-endpoint", Role = "endpoint" })
}

resource "aws_instance" "sandbox" {
  ami                    = var.ami_ids.sandbox
  instance_type          = var.instance_types.sandbox
  subnet_id              = var.subnet_ids.sandbox
  vpc_security_group_ids = [var.security_group_ids.sandbox]

  # No iam_instance_profile — same reasoning as endpoint above.
  associate_public_ip_address = false
  monitoring                  = var.enable_detailed_monitoring
  key_name                    = var.key_name

  root_block_device {
    volume_size = var.root_volume_sizes_gb.sandbox
    encrypted   = true
  }

  # IMDSv2-only, single-hop — no instance in this module ever allows the
  # legacy IMDSv1 GET-token-optional path (SSRF-to-credential-theft guard).
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required" # secret-scan: ignore (IMDSv2 mode enum, not a secret)
    http_put_response_hop_limit = 1
  }

  tags = merge(local.common_tags, { Name = "mirage-${var.environment}-sandbox", Role = "sandbox" })
}

resource "aws_instance" "attacker" {
  ami                    = var.ami_ids.attacker
  instance_type          = var.instance_types.attacker
  subnet_id              = var.subnet_ids.attacker
  vpc_security_group_ids = [var.security_group_ids.attacker]

  # No iam_instance_profile — a simulated intruder host holds no AWS
  # credentials under any circumstance.
  associate_public_ip_address = false
  monitoring                  = var.enable_detailed_monitoring
  key_name                    = var.key_name

  root_block_device {
    volume_size = var.root_volume_sizes_gb.attacker
    encrypted   = true
  }

  # IMDSv2-only, single-hop — no instance in this module ever allows the
  # legacy IMDSv1 GET-token-optional path (SSRF-to-credential-theft guard).
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required" # secret-scan: ignore (IMDSv2 mode enum, not a secret)
    http_put_response_hop_limit = 1
  }

  tags = merge(local.common_tags, { Name = "mirage-${var.environment}-attacker", Role = "attacker" })
}
