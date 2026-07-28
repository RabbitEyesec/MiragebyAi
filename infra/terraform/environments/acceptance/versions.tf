terraform {
  required_version = ">= 1.9, < 2.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.60"
    }
  }

  # Remote backend for acceptance/production — S3 with native S3 locking
  # (Terraform 1.9+; no separate DynamoDB lock table required). bucket/key
  # are supplied via `terraform init -backend-config=...` so this file has
  # no hardcoded account-specific values.
  backend "s3" {
    use_lockfile = true
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "mirage"
      Environment = var.environment
    }
  }
}
