# Step 9a: golden image pipeline variables. Mirrors infra/terraform's own
# variables.tf pattern (Profile A/B environment split, ADR-0007) — this
# template builds ONE golden image per environment, consuming the SAME
# sandbox subnet Step 2's VPC module already provisions (subnet_ids.sandbox
# output), never a separate network.

variable "environment" {
  type        = string
  description = "development or acceptance — selects which environment's sandbox subnet/security group this build launches into."
  validation {
    condition     = contains(["development", "acceptance"], var.environment)
    error_message = "environment must be development or acceptance."
  }
}

variable "aws_region" {
  type    = string
  default = "us-east-1"
}

variable "subnet_id" {
  type        = string
  description = "The sandbox subnet's ID (Step 2 Terraform output subnet_ids.sandbox) — the build instance launches here, never in a public subnet."
}

variable "vpc_id" {
  type = string
}

variable "instance_type" {
  type    = string
  default = "t3.large"
}

variable "manifest_kms_key_arn" {
  type        = string
  description = "KMS key ARN used to sign the build manifest (Step 9a: 'KMS-sign manifest'). LAB_VERIFICATION_REQUIRED — no key exists without a real AWS account."
}

variable "build_version" {
  type        = string
  description = "Versioned tag applied to the resulting AMI (Step 9a: 'a signed, versioned AMI'), e.g. 2026.07.25-1."
}

variable "fleet_url" {
  type        = string
  description = "Fleet Server URL for Elastic Agent enrollment. A fresh, per-build enrollment token (fleet_enrollment_token) is minted for every build — never baked into the image or committed."
}

variable "fleet_enrollment_token" {
  type      = string
  sensitive = true
}
