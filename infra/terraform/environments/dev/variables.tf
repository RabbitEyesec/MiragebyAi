variable "environment" {
  type    = string
  default = "development"
}

variable "aws_region" {
  type = string
}

variable "aws_account_id" {
  description = "12-digit AWS account ID — used only to build the evidence bucket name; never used as a bare credential."
  type        = string
}

variable "vpc_cidr" {
  type    = string
  default = "10.42.0.0/16"
}

variable "subnet_cidrs" {
  type = object({
    public_edge = string
    control     = string
    endpoint    = string
    sandbox     = string
    attacker    = string
  })
  default = {
    public_edge = "10.42.0.0/22"
    control     = "10.42.4.0/22"
    endpoint    = "10.42.8.0/22"
    sandbox     = "10.42.12.0/22"
    attacker    = "10.42.16.0/22"
  }
}

variable "availability_zone" {
  type = string
}

variable "allowed_analyst_cidr" {
  description = "CIDR allowed to reach the public edge on 443. Set to your own IP/32 for dev — never leave at 0.0.0.0/0 outside a short-lived throwaway session."
  type        = string
}

variable "object_lock_retention_days" {
  type    = number
  default = 7 # short for disposable dev environments; acceptance/production use 90+.
}

variable "log_retention_days" {
  type    = number
  default = 14
}

variable "enable_canary" {
  type    = bool
  default = false
}

variable "enable_compute" {
  description = "Provision the five topology EC2 instances (broker/control/endpoint/sandbox/attacker). Defaults off for dev — most dev work uses the local Docker Compose stack (infra/compose), not real EC2."
  type        = bool
  default     = false
}

variable "compute_ami_ids" {
  description = "AMI ID per instance role — see infra/terraform/modules/compute/variables.tf. Placeholders must be overridden with real, region-specific AMI IDs before apply."
  type = object({
    broker   = string
    control  = string
    endpoint = string
    sandbox  = string
    attacker = string
  })
  default = {
    broker   = "ami-LAB_VERIFICATION_REQUIRED"
    control  = "ami-LAB_VERIFICATION_REQUIRED"
    endpoint = "ami-LAB_VERIFICATION_REQUIRED"
    sandbox  = "ami-LAB_VERIFICATION_REQUIRED"
    attacker = "ami-LAB_VERIFICATION_REQUIRED"
  }
}

variable "compute_key_name" {
  description = "EC2 key pair name for interactive/break-glass access. Null disables key-pair login entirely."
  type        = string
  default     = null
}
variable "canary_lambda_zip_path" {
  type    = string
  default = "canary-collector.zip"
}
variable "canary_signing_secret_arn" {
  type    = string
  default = "LAB_VERIFICATION_REQUIRED"
}
variable "canary_ingestion_url" {
  type    = string
  default = "https://LAB_VERIFICATION_REQUIRED.invalid/internal/canary/callback"
}
variable "canary_domain_name" {
  type    = string
  default = "canary.LAB_VERIFICATION_REQUIRED.invalid"
}
variable "canary_certificate_arn" {
  type    = string
  default = "LAB_VERIFICATION_REQUIRED"
}
variable "canary_hosted_zone_id" {
  type    = string
  default = "LAB_VERIFICATION_REQUIRED"
}
