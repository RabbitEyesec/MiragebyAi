# Mirage development environment (Profile A, Appendix L). Provisions the
# Step 2 AWS foundation only — VPC, IAM, evidence bucket, CloudWatch log
# groups. Later stages' resources (Fleet Server, sandbox AMI instances, RD
# Gateway, etc.) are provisioned by their own stage's Terraform, layered on
# top of these outputs — none of that exists yet in Prompt 1.

module "vpc" {
  source = "../../modules/vpc"

  environment          = var.environment
  vpc_cidr             = var.vpc_cidr
  subnet_cidrs         = var.subnet_cidrs
  availability_zone    = var.availability_zone
  allowed_analyst_cidr = var.allowed_analyst_cidr
}

module "evidence" {
  source = "../../modules/evidence"

  environment                = var.environment
  bucket_name                = "mirage-${var.environment}-evidence-${var.aws_account_id}"
  object_lock_retention_days = var.object_lock_retention_days

  # The single control_node role (ADR-0011) is the only principal that ever
  # signs manifests or reads/writes evidence bytes — computed as a plain ARN
  # string from module.iam's own role-naming convention, not a module.iam.*
  # reference (that would create an iam<->evidence cycle: iam already takes
  # these two key ARNs as input).
  signing_key_authorized_principal_arns    = ["arn:aws:iam::${var.aws_account_id}:role/mirage-${var.environment}-control-node"]
  encryption_key_authorized_principal_arns = ["arn:aws:iam::${var.aws_account_id}:role/mirage-${var.environment}-control-node"]
}

resource "aws_kms_key" "logs" {
  description             = "Mirage control-plane CloudWatch log group encryption key (${var.environment})"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  tags                    = { Project = "mirage", Environment = var.environment }
}

resource "aws_kms_alias" "logs" {
  name          = "alias/mirage-${var.environment}-logs"
  target_key_id = aws_kms_key.logs.key_id
}

resource "aws_cloudwatch_log_group" "control_plane" {
  for_each = toset([
    "mirage-api", "mirage-worker", "mirage-outbox-relay",
    "mirage-agent-ingestion", "mirage-sandbox-gateway",
  ])
  name              = "/mirage/${var.environment}/${each.value}"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.logs.arn

  tags = {
    Project     = "mirage"
    Environment = var.environment
    Service     = each.value
  }
}

module "iam" {
  source = "../../modules/iam"

  environment = var.environment
  secrets_manager_secret_arns = [
    for name in ["postgres", "nats", "elastic", "keycloak", "step-ca", "ai-provider", "fleet"] :
    "arn:aws:secretsmanager:${var.aws_region}:${var.aws_account_id}:secret:mirage/${var.environment}/${name}-*"
  ]
  evidence_bucket_arn         = module.evidence.bucket_arn
  signing_key_arn             = module.evidence.signing_key_arn
  evidence_encryption_key_arn = module.evidence.evidence_encryption_key_arn
  log_group_arns              = [for lg in aws_cloudwatch_log_group.control_plane : "${lg.arn}:*"]
}

module "canary" {
  count  = var.enable_canary ? 1 : 0
  source = "../../modules/canary"

  environment        = var.environment
  lambda_zip_path    = var.canary_lambda_zip_path
  signing_secret_arn = var.canary_signing_secret_arn
  ingestion_url      = var.canary_ingestion_url
  domain_name        = var.canary_domain_name
  certificate_arn    = var.canary_certificate_arn
  hosted_zone_id     = var.canary_hosted_zone_id
}

module "compute" {
  count  = var.enable_compute ? 1 : 0
  source = "../../modules/compute"

  environment                        = var.environment
  subnet_ids                         = module.vpc.subnet_ids
  security_group_ids                 = module.vpc.security_group_ids
  control_node_instance_profile_name = module.iam.control_node_instance_profile_name
  ami_ids                            = var.compute_ami_ids
  key_name                           = var.compute_key_name
}
