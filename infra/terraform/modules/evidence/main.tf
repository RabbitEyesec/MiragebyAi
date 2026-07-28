# Evidence storage + signing key (Step 2 local scope; consumed fully by
# Stage 5 / Step 11, not built in Prompt 1). Provisioned now because Step 2
# is where the spec places "evidence S3 bucket" in the build order.

locals {
  common_tags = {
    Project     = "mirage"
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}

data "aws_caller_identity" "current" {}

# ---------------------------------------------------------------------------
# KMS key policies — a restrictive, least-privilege policy per key rather
# than relying on the AWS-default "account root has kms:* " policy alone.
# The root statement is kept (AWS requires at least one IAM-manageable
# principal on every key policy or the key becomes unmanageable), but actual
# key USAGE (Sign/GetPublicKey, Decrypt/GenerateDataKey) is additionally
# scoped to only the caller-supplied authorized-principal ARNs — e.g.
# mirage-worker's role, never "any IAM principal in the account with a
# permissive-enough identity policy." Computed from var.*_authorized_principal_arns
# (plain ARN strings the root Terraform config builds from the environment/
# role-name convention), not a live module.iam reference, to avoid an
# iam<->evidence circular module dependency (iam already takes these keys'
# ARNs as input).
# ---------------------------------------------------------------------------

data "aws_iam_policy_document" "signing_key_policy" {
  statement {
    sid       = "EnableRootAccountManagement"
    actions   = ["kms:*"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
  }

  dynamic "statement" {
    for_each = length(var.signing_key_authorized_principal_arns) > 0 ? [1] : []
    content {
      sid       = "AllowScopedSigningUsage"
      actions   = ["kms:Sign", "kms:GetPublicKey", "kms:DescribeKey"]
      resources = ["*"]
      principals {
        type        = "AWS"
        identifiers = var.signing_key_authorized_principal_arns
      }
    }
  }
}

data "aws_iam_policy_document" "evidence_encryption_key_policy" {
  statement {
    sid       = "EnableRootAccountManagement"
    actions   = ["kms:*"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
  }

  dynamic "statement" {
    for_each = length(var.encryption_key_authorized_principal_arns) > 0 ? [1] : []
    content {
      sid       = "AllowScopedEncryptDecryptUsage"
      actions   = ["kms:Decrypt", "kms:GenerateDataKey", "kms:DescribeKey"]
      resources = ["*"]
      principals {
        type        = "AWS"
        identifiers = var.encryption_key_authorized_principal_arns
      }
    }
  }

  # S3 needs to use the key on the bucket owner's behalf for SSE-KMS.
  statement {
    sid       = "AllowS3ServiceViaBucketOwner"
    actions   = ["kms:Decrypt", "kms:GenerateDataKey"]
    resources = ["*"]
    principals {
      type        = "Service"
      identifiers = ["s3.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "kms:CallerAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }
}

# ---------------------------------------------------------------------------
# KMS asymmetric signing key — RSASSA_PSS_SHA_256 (spec: "AWS KMS asymmetric
# (RSASSA_PSS_SHA_256)"). Used to sign evidence export manifests and Packer
# AMI build manifests (Steps 9a, 11 — manifest signing only, never used to
# encrypt/decrypt bulk evidence bytes, which use a separate SSE-KMS key below).
# ---------------------------------------------------------------------------

resource "aws_kms_key" "signing" {
  description              = "Mirage evidence/manifest signing key (${var.environment})"
  key_usage                = "SIGN_VERIFY"
  customer_master_key_spec = "RSA_4096"
  deletion_window_in_days  = var.kms_deletion_window_days
  enable_key_rotation      = false # AWS does not support automatic rotation for asymmetric keys.
  policy                   = data.aws_iam_policy_document.signing_key_policy.json

  tags = merge(local.common_tags, { Name = "mirage-${var.environment}-signing-key" })
}

resource "aws_kms_alias" "signing" {
  name          = "alias/mirage-${var.environment}-signing"
  target_key_id = aws_kms_key.signing.key_id
}

# Separate symmetric key for SSE-KMS bulk encryption of evidence bytes at
# rest — kept distinct from the signing key so a bulk-encryption key rotation
# never invalidates already-issued signatures.
resource "aws_kms_key" "evidence_encryption" {
  description             = "Mirage evidence bucket SSE-KMS encryption key (${var.environment})"
  key_usage               = "ENCRYPT_DECRYPT"
  deletion_window_in_days = var.kms_deletion_window_days
  enable_key_rotation     = true
  policy                  = data.aws_iam_policy_document.evidence_encryption_key_policy.json

  tags = merge(local.common_tags, { Name = "mirage-${var.environment}-evidence-encryption-key" })
}

resource "aws_kms_alias" "evidence_encryption" {
  name          = "alias/mirage-${var.environment}-evidence-encryption"
  target_key_id = aws_kms_key.evidence_encryption.key_id
}

# ---------------------------------------------------------------------------
# Evidence bucket — versioned, Object Lock (WORM) enabled at creation
# (required — Object Lock cannot be enabled after bucket creation), SSE-KMS.
# ---------------------------------------------------------------------------

resource "aws_s3_bucket" "evidence" {
  bucket              = var.bucket_name
  object_lock_enabled = true

  tags = merge(local.common_tags, { Name = var.bucket_name, Purpose = "evidence-worm" })
}

resource "aws_s3_bucket_versioning" "evidence" {
  bucket = aws_s3_bucket.evidence.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_object_lock_configuration" "evidence" {
  bucket = aws_s3_bucket.evidence.id
  rule {
    default_retention {
      mode = "COMPLIANCE"
      days = var.object_lock_retention_days
    }
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "evidence" {
  bucket = aws_s3_bucket.evidence.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.evidence_encryption.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "evidence" {
  bucket                  = aws_s3_bucket.evidence.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# ---------------------------------------------------------------------------
# Server access logging — a forensic-evidence bucket is exactly the case
# where "who read/wrote what, when" matters most. Logs go to a SEPARATE
# bucket (S3 requires this) with its own public-access block; the log
# bucket itself is not versioned/Object-Locked (it is not evidence, it is
# an audit trail ABOUT evidence access, already immutable-enough via
# S3's own append-only access log delivery).
# ---------------------------------------------------------------------------

# tfsec ignore below: this IS the log destination bucket; S3 does not
# support (and AWS does not recommend) chaining a log bucket's own access
# logs into itself or another bucket indefinitely.
#tfsec:ignore:aws-s3-enable-bucket-logging
resource "aws_s3_bucket" "evidence_access_logs" {
  bucket = "${var.bucket_name}-access-logs"

  tags = merge(local.common_tags, { Name = "${var.bucket_name}-access-logs", Purpose = "evidence-access-logs" })
}

resource "aws_s3_bucket_server_side_encryption_configuration" "evidence_access_logs" {
  bucket = aws_s3_bucket.evidence_access_logs.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.evidence_encryption.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_versioning" "evidence_access_logs" {
  bucket = aws_s3_bucket.evidence_access_logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_public_access_block" "evidence_access_logs" {
  bucket                  = aws_s3_bucket.evidence_access_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "evidence_access_logs" {
  bucket = aws_s3_bucket.evidence_access_logs.id
  rule {
    id     = "expire-old-access-logs"
    status = "Enabled"
    filter {}
    expiration {
      days = 365
    }
  }
}

resource "aws_s3_bucket_logging" "evidence" {
  bucket = aws_s3_bucket.evidence.id

  target_bucket = aws_s3_bucket.evidence_access_logs.id
  target_prefix = "evidence-access-logs/"
}

# The sandbox subnet does NOT get direct S3 access — evidence bytes flow
# through mirage-worker/mirage-report-worker in the control subnet only, per
# Step 2's "sandbox cannot reach evidence storage directly unless explicitly
# required and policy-approved" (no such exception is configured by
# default). Enforced two ways, deliberately WITHOUT a bucket policy that
# hard-denies non-VPC-endpoint traffic (that would risk locking out
# `terraform apply` itself when run from outside the VPC on a future
# change — see ARCHITECTURE_DECISIONS.md):
#   1. Network: the S3 Gateway VPC endpoint (infra/terraform/modules/vpc)
#      is associated with ONLY the control subnet's route table — sandbox
#      and endpoint subnets have no route to it at all.
#   2. Identity: sandbox/endpoint agents (MirageSpider, MirageEnvironmentController,
#      MirageEndpoint) authenticate via step-ca mTLS certificates (ADR-0002),
#      never AWS IAM credentials — they cannot call any AWS API regardless
#      of network path, because they hold no AWS credentials at all.
# IAM policy for which ROLES may reach this bucket lives in
# infra/terraform/modules/iam (control-plane roles only).
