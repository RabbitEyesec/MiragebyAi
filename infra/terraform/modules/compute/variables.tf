variable "environment" {
  type        = string
  description = "Environment name; applied as the Environment tag."
}

variable "subnet_ids" {
  description = "The five subnet IDs from infra/terraform/modules/vpc's subnet_ids output."
  type = object({
    public_edge = string
    control     = string
    endpoint    = string
    sandbox     = string
    attacker    = string
  })
}

variable "security_group_ids" {
  description = "The security group IDs from infra/terraform/modules/vpc's security_group_ids output."
  type = object({
    public_edge = string
    control     = string
    endpoint    = string
    sandbox     = string
    attacker    = string
  })
}

variable "control_node_instance_profile_name" {
  description = "From infra/terraform/modules/iam's control_node_instance_profile_name output. Attached ONLY to the control instance — endpoint/sandbox/attacker/broker get no IAM instance profile at all (ADR-0002, ADR-0011: they authenticate via step-ca mTLS, never AWS credentials)."
  type        = string
}

# ---------------------------------------------------------------------------
# AMI IDs — each is a real, region-specific artifact this environment cannot
# produce (broker/control are an official Ubuntu 24.04 AMI; endpoint/sandbox
# are Step 9a's Packer golden Windows AMI; attacker is a Kali Linux AMI).
# Defaulted to the project's established "LAB_VERIFICATION_REQUIRED"
# placeholder convention (see environments/*/variables.tf's canary_* vars)
# so `terraform validate`/`fmt` stay real and offline; a real `apply` must
# override every one of these with an actual AMI ID.
# ---------------------------------------------------------------------------

variable "ami_ids" {
  description = "AMI ID per instance role. Placeholders must be overridden with real, region-specific AMI IDs before apply."
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

variable "instance_types" {
  description = "EC2 instance type per role."
  type = object({
    broker   = string
    control  = string
    endpoint = string
    sandbox  = string
    attacker = string
  })
  default = {
    broker   = "t3.small"
    control  = "t3.large"
    endpoint = "t3.xlarge" # Windows employee VM
    sandbox  = "t3.xlarge" # Windows sandbox VM
    attacker = "t3.medium" # Kali
  }
}

variable "root_volume_sizes_gb" {
  description = "Root EBS volume size (GiB) per role."
  type = object({
    broker   = number
    control  = number
    endpoint = number
    sandbox  = number
    attacker = number
  })
  default = {
    broker   = 20
    control  = 50
    endpoint = 100
    sandbox  = 100
    attacker = 40
  }
}

variable "key_name" {
  description = "EC2 key pair name for interactive access (control node break-glass, attacker Kali). Null disables key-pair-based login entirely (endpoint/sandbox use it only for Windows initial-password retrieval, never ongoing access)."
  type        = string
  default     = null
}

variable "enable_detailed_monitoring" {
  type    = bool
  default = true
}
