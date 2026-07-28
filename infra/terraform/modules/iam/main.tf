# IAM roles for the five Prompt-1 control-plane services (Step 2).
#
# The spec locks "Server packaging: Docker Compose (single control node)" —
# all five services run as containers on ONE EC2 instance, not as separate
# EC2/ECS tasks. Plain Docker Compose has no per-container IAM mechanism
# (that requires ECS/Fargate task roles or a sidecar credential broker,
# neither of which is in the locked technology list). So this module defines
# a distinct, least-privilege IAM POLICY per service — for documentation,
# audit, and a future ECS/Fargate migration where per-task roles are
# trivial — and attaches their UNION to ONE "control node" instance role,
# which is what Docker Compose can actually use today. See
# ARCHITECTURE_DECISIONS.md ADR-0011 for the full reasoning; this is a
# genuine current limitation, not hidden: any container escape on the
# control node has the union of all five services' AWS permissions, not
# just its own. Secrets themselves remain least-privilege at the
# Secrets Manager resource level regardless (each service's own code only
# ever reads the secret names it needs — see docs/runbooks/secrets.md).

locals {
  common_tags = {
    Project     = "mirage"
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}

data "aws_iam_policy_document" "ec2_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

# ---------------------------------------------------------------------------
# Per-service least-privilege policy documents
# ---------------------------------------------------------------------------

data "aws_iam_policy_document" "mirage_api" {
  statement {
    sid       = "ReadOwnSecrets"
    actions   = ["secretsmanager:GetSecretValue"]
    resources = [for arn in var.secrets_manager_secret_arns : arn if !can(regex("/(ai-provider|installer-signing|canary)$", arn))]
  }
  statement {
    sid       = "SelfHealthCloudWatch"
    actions   = ["cloudwatch:PutMetricData"]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "cloudwatch:namespace"
      values   = ["Mirage"]
    }
  }
}

# tfsec ignore below: the EvidenceReadWrite statement's object-level S3
# actions are necessarily scoped to "<bucket-arn>/*"; there is no narrower
# resource ARN for "any object in this specific bucket" in the S3 IAM model.
# The policy is already scoped to exactly ONE bucket (var.evidence_bucket_arn,
# not "arn:aws:s3:::*"), which is the real least-privilege boundary here.
#tfsec:ignore:aws-iam-no-policy-wildcards
data "aws_iam_policy_document" "mirage_worker" {
  statement {
    sid       = "ReadOwnSecretsIncludingAI"
    actions   = ["secretsmanager:GetSecretValue"]
    resources = [for arn in var.secrets_manager_secret_arns : arn if !can(regex("/(installer-signing|canary)$", arn))]
  }
  statement {
    sid       = "EvidenceReadWrite"
    actions   = ["s3:GetObject", "s3:PutObject", "s3:PutObjectRetention"]
    resources = ["${var.evidence_bucket_arn}/*"]
  }
  statement {
    sid       = "EvidenceListBucket"
    actions   = ["s3:ListBucket"]
    resources = [var.evidence_bucket_arn]
  }
  statement {
    sid       = "SignManifests"
    actions   = ["kms:Sign", "kms:GetPublicKey"]
    resources = [var.signing_key_arn]
  }
  statement {
    sid       = "EvidenceEncryption"
    actions   = ["kms:Decrypt", "kms:GenerateDataKey"]
    resources = [var.evidence_encryption_key_arn]
  }
}

data "aws_iam_policy_document" "mirage_outbox_relay" {
  statement {
    sid       = "ReadOwnSecrets"
    actions   = ["secretsmanager:GetSecretValue"]
    resources = [for arn in var.secrets_manager_secret_arns : arn if can(regex("/(postgres|nats)$", arn))]
  }
}

data "aws_iam_policy_document" "mirage_agent_ingestion" {
  statement {
    sid       = "ReadOwnSecrets"
    actions   = ["secretsmanager:GetSecretValue"]
    resources = [for arn in var.secrets_manager_secret_arns : arn if can(regex("/(postgres|nats|step-ca|fleet)$", arn))]
  }
}

data "aws_iam_policy_document" "mirage_sandbox_gateway" {
  statement {
    sid       = "ReadOwnSecrets"
    actions   = ["secretsmanager:GetSecretValue"]
    resources = [for arn in var.secrets_manager_secret_arns : arn if can(regex("/(postgres|nats|step-ca)$", arn))]
  }
}

data "aws_iam_policy_document" "logs" {
  count = length(var.log_group_arns) > 0 ? 1 : 0
  statement {
    sid       = "WriteOwnLogGroups"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents", "logs:DescribeLogStreams"]
    resources = var.log_group_arns
  }
}

# ---------------------------------------------------------------------------
# Named policies (attachable individually — used directly once services move
# to ECS/Fargate task roles; combined below for the current single-EC2-node
# Docker Compose deployment).
# ---------------------------------------------------------------------------

resource "aws_iam_policy" "mirage_api" {
  name   = "mirage-${var.environment}-mirage-api"
  policy = data.aws_iam_policy_document.mirage_api.json
  tags   = local.common_tags
}

resource "aws_iam_policy" "mirage_worker" {
  name   = "mirage-${var.environment}-mirage-worker"
  policy = data.aws_iam_policy_document.mirage_worker.json
  tags   = local.common_tags
}

resource "aws_iam_policy" "mirage_outbox_relay" {
  name   = "mirage-${var.environment}-mirage-outbox-relay"
  policy = data.aws_iam_policy_document.mirage_outbox_relay.json
  tags   = local.common_tags
}

resource "aws_iam_policy" "mirage_agent_ingestion" {
  name   = "mirage-${var.environment}-mirage-agent-ingestion"
  policy = data.aws_iam_policy_document.mirage_agent_ingestion.json
  tags   = local.common_tags
}

resource "aws_iam_policy" "mirage_sandbox_gateway" {
  name   = "mirage-${var.environment}-mirage-sandbox-gateway"
  policy = data.aws_iam_policy_document.mirage_sandbox_gateway.json
  tags   = local.common_tags
}

# ---------------------------------------------------------------------------
# Control-node EC2 instance role — union of the five policies above, matching
# the current Docker-Compose-single-node deployment model.
# ---------------------------------------------------------------------------

resource "aws_iam_role" "control_node" {
  name               = "mirage-${var.environment}-control-node"
  assume_role_policy = data.aws_iam_policy_document.ec2_assume.json
  tags               = local.common_tags
}

resource "aws_iam_role_policy_attachment" "control_node_api" {
  role       = aws_iam_role.control_node.name
  policy_arn = aws_iam_policy.mirage_api.arn
}

resource "aws_iam_role_policy_attachment" "control_node_worker" {
  role       = aws_iam_role.control_node.name
  policy_arn = aws_iam_policy.mirage_worker.arn
}

resource "aws_iam_role_policy_attachment" "control_node_outbox_relay" {
  role       = aws_iam_role.control_node.name
  policy_arn = aws_iam_policy.mirage_outbox_relay.arn
}

resource "aws_iam_role_policy_attachment" "control_node_agent_ingestion" {
  role       = aws_iam_role.control_node.name
  policy_arn = aws_iam_policy.mirage_agent_ingestion.arn
}

resource "aws_iam_role_policy_attachment" "control_node_sandbox_gateway" {
  role       = aws_iam_role.control_node.name
  policy_arn = aws_iam_policy.mirage_sandbox_gateway.arn
}

resource "aws_iam_role_policy" "control_node_logs" {
  count  = length(var.log_group_arns) > 0 ? 1 : 0
  name   = "mirage-${var.environment}-control-node-logs"
  role   = aws_iam_role.control_node.id
  policy = data.aws_iam_policy_document.logs[0].json
}

resource "aws_iam_instance_profile" "control_node" {
  name = "mirage-${var.environment}-control-node"
  role = aws_iam_role.control_node.name
  tags = local.common_tags
}

# Endpoint and sandbox EC2 instances get NO IAM role at all — they
# authenticate exclusively via step-ca mTLS certificates (ADR-0002). This is
# intentional and matches the security boundary: an instance profile would
# be one more thing to keep off the sandbox permanently.
