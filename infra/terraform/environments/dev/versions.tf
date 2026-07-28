terraform {
  required_version = ">= 1.9, < 2.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.60"
    }
  }

  # Local backend for Profile A (dev) — a single engineer's disposable
  # environment. Acceptance/production use a remote backend (S3 + native
  # locking); see environments/acceptance/versions.tf. State is git-ignored
  # regardless (.gitignore: **/.terraform/*, *.tfstate*).
  backend "local" {
    path = "terraform.tfstate"
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
