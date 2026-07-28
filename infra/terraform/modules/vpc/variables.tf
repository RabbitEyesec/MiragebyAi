variable "environment" {
  description = "Environment name (development | acceptance | production). Applied as the Environment tag."
  type        = string
}

variable "vpc_cidr" {
  description = "CIDR block for the Mirage VPC."
  type        = string
}

variable "subnet_cidrs" {
  description = "CIDR blocks for the five subnets (spec §5 topology)."
  type = object({
    public_edge = string
    control     = string
    endpoint    = string
    sandbox     = string
    attacker    = string
  })
}

variable "availability_zone" {
  description = "Single AZ for Profile A (dev). Acceptance/production may extend this module to multi-AZ later — not required for Prompt 1's numeric Definition of Done, which is measured on Profile B but does not require multi-AZ HA."
  type        = string
}

variable "allowed_analyst_cidr" {
  description = "CIDR allowed to reach the public edge on 443 (analyst browser / VPN egress). Never 0.0.0.0/0 in acceptance/production."
  type        = string
  default     = "0.0.0.0/0"
}

variable "broker_backend_ports" {
  description = "Ports the public-edge brokers forward to ENDPOINT/SANDBOX backends (HTTP 443, SSH 22, RDP 3389 — Appendix H)."
  type        = list(number)
  default     = [443, 22, 3389]
}
