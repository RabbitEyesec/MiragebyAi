variable "environment" {
  type        = string
  description = "Environment name; applied as the Environment tag and in the bucket name."
}

variable "bucket_name" {
  type        = string
  description = "Globally-unique evidence bucket name (e.g. mirage-<environment>-evidence-<account_id>)."
}

variable "object_lock_retention_days" {
  type        = number
  default     = 90
  description = "Default Object Lock (WORM) retention in COMPLIANCE mode — evidence cannot be deleted or overwritten before this elapses, even by the account root."
}

variable "kms_deletion_window_days" {
  type        = number
  default     = 30
  description = "KMS key deletion window (7-30 days) — a safety margin against accidental key deletion breaking evidence verification."
}

variable "signing_key_authorized_principal_arns" {
  description = "IAM role/user ARNs allowed to Sign/GetPublicKey with the signing key, beyond the mandatory account-root statement — in practice the single control_node role (ADR-0011: one role, union of five services' policies, since mirage-worker signs manifests). Computed by the caller from the module.iam role-naming convention as a plain ARN string, not a module.iam.* attribute reference, to avoid an iam<->evidence dependency cycle (iam already takes this module's key ARNs as input)."
  type        = list(string)
  default     = []
}

variable "encryption_key_authorized_principal_arns" {
  description = "IAM role/user ARNs allowed to Decrypt/GenerateDataKey with the evidence encryption key, beyond the mandatory account-root statement."
  type        = list(string)
  default     = []
}
