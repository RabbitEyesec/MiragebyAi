variable "environment" {
  type = string
}

variable "secrets_manager_secret_arns" {
  description = "ARNs of the mirage/<environment>/{postgres,nats,elastic,keycloak,step-ca,ai-provider,fleet} secrets (docs/runbooks/secrets.md). installer-signing and canary are deliberately excluded from the control-node role — see that doc's 'never exposed to' rules."
  type        = list(string)
}

variable "evidence_bucket_arn" {
  type = string
}

variable "signing_key_arn" {
  type = string
}

variable "evidence_encryption_key_arn" {
  type = string
}

variable "log_group_arns" {
  type    = list(string)
  default = []
}
