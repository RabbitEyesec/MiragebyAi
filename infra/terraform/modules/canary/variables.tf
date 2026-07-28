variable "environment" {
  type = string
}

variable "project" {
  type    = string
  default = "mirage"
}

variable "lambda_zip_path" {
  type = string
}

variable "signing_secret_arn" {
  type = string
}

variable "ingestion_url" {
  type = string
}

variable "domain_name" {
  type = string
}

variable "certificate_arn" {
  type = string
}

variable "hosted_zone_id" {
  type = string
}

variable "log_retention_days" {
  type    = number
  default = 30
}

variable "waf_rate_limit_per_five_minutes" {
  type        = number
  default     = 1000
  description = "Maximum requests per source IP in a five-minute WAF window."
}
