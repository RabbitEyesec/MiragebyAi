# Mirage VPC — five subnets, private by default (spec §5 topology; Step 2).
#
# PUBLIC (edge only): Nginx/HTTP broker | SSH bastion | RD Gateway | VPN
# CONTROL  (private): mirage-api, worker, gateway, ingestion, outbox-relay,
#                     postgres, nats, elasticsearch, kibana, keycloak, step-ca
# ENDPOINT (private): Windows employee VM
# SANDBOX  (private): Windows sandbox VM -- dials OUT only
# ATTACKER (private): Kali -- reaches broker entry points, NOTHING else
#
# No NAT gateway anywhere. S3/KMS/Secrets Manager reachable only via VPC
# endpoints scoped to the control subnet's security group.

locals {
  common_tags = {
    Project     = "mirage"
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}

resource "aws_vpc" "this" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = merge(local.common_tags, { Name = "mirage-${var.environment}-vpc" })
}

# ---------------------------------------------------------------------------
# VPC Flow Logs — every packet accepted/rejected across every ENI in the VPC,
# to a KMS-encrypted CloudWatch log group. This is the network-level audit
# trail that proves the isolation rules below are actually holding in a real
# account (tfsec aws-ec2-require-vpc-flow-logs-for-all-vpcs).
# ---------------------------------------------------------------------------

resource "aws_kms_key" "flow_logs" {
  description             = "Mirage VPC flow logs encryption key (${var.environment})"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  tags                    = merge(local.common_tags, { Name = "mirage-${var.environment}-flow-logs-key" })
}

resource "aws_kms_alias" "flow_logs" {
  name          = "alias/mirage-${var.environment}-flow-logs"
  target_key_id = aws_kms_key.flow_logs.key_id
}

resource "aws_cloudwatch_log_group" "flow_logs" {
  name              = "/mirage/${var.environment}/vpc-flow-logs"
  retention_in_days = 90
  kms_key_id        = aws_kms_key.flow_logs.arn
  tags              = merge(local.common_tags, { Name = "mirage-${var.environment}-vpc-flow-logs" })
}

data "aws_iam_policy_document" "flow_logs_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["vpc-flow-logs.amazonaws.com"]
    }
  }
}

# tfsec ignore below: ":*" here means "log streams within this one specific
# log group", the standard CloudWatch Logs IAM pattern (a log stream ARN is
# <log-group-arn>:log-stream:<name>, and the service creates stream names
# dynamically) — already scoped to exactly the flow-log group created above,
# not a broader wildcard.
#tfsec:ignore:aws-iam-no-policy-wildcards
data "aws_iam_policy_document" "flow_logs_publish" {
  statement {
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents", "logs:DescribeLogGroups", "logs:DescribeLogStreams"]
    resources = ["${aws_cloudwatch_log_group.flow_logs.arn}:*"]
  }
}

resource "aws_iam_role" "flow_logs" {
  name               = "mirage-${var.environment}-vpc-flow-logs"
  assume_role_policy = data.aws_iam_policy_document.flow_logs_assume.json
  tags               = local.common_tags
}

resource "aws_iam_role_policy" "flow_logs_publish" {
  name   = "mirage-${var.environment}-vpc-flow-logs-publish"
  role   = aws_iam_role.flow_logs.id
  policy = data.aws_iam_policy_document.flow_logs_publish.json
}

resource "aws_flow_log" "this" {
  vpc_id                   = aws_vpc.this.id
  traffic_type             = "ALL"
  log_destination_type     = "cloud-watch-logs"
  log_destination          = aws_cloudwatch_log_group.flow_logs.arn
  iam_role_arn             = aws_iam_role.flow_logs.arn
  max_aggregation_interval = 60

  tags = merge(local.common_tags, { Name = "mirage-${var.environment}-vpc-flow-log" })
}

# ---------------------------------------------------------------------------
# Subnets — only the public edge subnet auto-assigns public IPs. Every
# private subnet is created with map_public_ip_on_launch = false, and no
# instance in this module's design ever attaches an Elastic IP to a private
# subnet ENI (Step 2 local acceptance: "No private instance is configured
# with a public IP").
# ---------------------------------------------------------------------------

# tfsec ignore below: intentional — this is the spec's "public edge" subnet
# (Nginx broker / SSH bastion / RD Gateway), the ONLY subnet meant to be
# internet-reachable (§5). Every other subnet below is private with no
# public IP, which is the actual Step 2 rule being enforced ("No private
# instance is configured with a public IP") — see
# tests/unit/test_terraform_network_policy.py.
#tfsec:ignore:aws-ec2-no-public-ip-subnet
resource "aws_subnet" "public_edge" {
  vpc_id                  = aws_vpc.this.id
  cidr_block              = var.subnet_cidrs.public_edge
  availability_zone       = var.availability_zone
  map_public_ip_on_launch = true

  tags = merge(local.common_tags, { Name = "mirage-${var.environment}-public-edge", Tier = "public" })
}

resource "aws_subnet" "control" {
  vpc_id                  = aws_vpc.this.id
  cidr_block              = var.subnet_cidrs.control
  availability_zone       = var.availability_zone
  map_public_ip_on_launch = false

  tags = merge(local.common_tags, { Name = "mirage-${var.environment}-control", Tier = "private" })
}

resource "aws_subnet" "endpoint" {
  vpc_id                  = aws_vpc.this.id
  cidr_block              = var.subnet_cidrs.endpoint
  availability_zone       = var.availability_zone
  map_public_ip_on_launch = false

  tags = merge(local.common_tags, { Name = "mirage-${var.environment}-endpoint", Tier = "private" })
}

resource "aws_subnet" "sandbox" {
  vpc_id                  = aws_vpc.this.id
  cidr_block              = var.subnet_cidrs.sandbox
  availability_zone       = var.availability_zone
  map_public_ip_on_launch = false

  tags = merge(local.common_tags, { Name = "mirage-${var.environment}-sandbox", Tier = "private" })
}

resource "aws_subnet" "attacker" {
  vpc_id                  = aws_vpc.this.id
  cidr_block              = var.subnet_cidrs.attacker
  availability_zone       = var.availability_zone
  map_public_ip_on_launch = false

  tags = merge(local.common_tags, { Name = "mirage-${var.environment}-attacker", Tier = "private" })
}

# ---------------------------------------------------------------------------
# Internet Gateway — attached ONLY to the public edge subnet's route table.
# No NAT gateway is ever created (S3/KMS/Secrets go via VPC endpoints).
# ---------------------------------------------------------------------------

resource "aws_internet_gateway" "this" {
  vpc_id = aws_vpc.this.id
  tags   = merge(local.common_tags, { Name = "mirage-${var.environment}-igw" })
}

resource "aws_route_table" "public_edge" {
  vpc_id = aws_vpc.this.id
  tags   = merge(local.common_tags, { Name = "mirage-${var.environment}-rt-public-edge" })
}

resource "aws_route" "public_edge_internet" {
  route_table_id         = aws_route_table.public_edge.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.this.id
}

resource "aws_route_table_association" "public_edge" {
  subnet_id      = aws_subnet.public_edge.id
  route_table_id = aws_route_table.public_edge.id
}

# Private subnets each get their own route table with ONLY the implicit
# local VPC route (added automatically by AWS) — no default route out, no
# NAT, no IGW. They differ only so each subnet's egress can later be
# restricted independently (e.g. VPC endpoint route entries per Tier) without
# touching the others.
resource "aws_route_table" "control" {
  vpc_id = aws_vpc.this.id
  tags   = merge(local.common_tags, { Name = "mirage-${var.environment}-rt-control" })
}

resource "aws_route_table" "endpoint" {
  vpc_id = aws_vpc.this.id
  tags   = merge(local.common_tags, { Name = "mirage-${var.environment}-rt-endpoint" })
}

resource "aws_route_table" "sandbox" {
  vpc_id = aws_vpc.this.id
  tags   = merge(local.common_tags, { Name = "mirage-${var.environment}-rt-sandbox" })
}

resource "aws_route_table" "attacker" {
  vpc_id = aws_vpc.this.id
  tags   = merge(local.common_tags, { Name = "mirage-${var.environment}-rt-attacker" })
}

resource "aws_route_table_association" "control" {
  subnet_id      = aws_subnet.control.id
  route_table_id = aws_route_table.control.id
}

resource "aws_route_table_association" "endpoint" {
  subnet_id      = aws_subnet.endpoint.id
  route_table_id = aws_route_table.endpoint.id
}

resource "aws_route_table_association" "sandbox" {
  subnet_id      = aws_subnet.sandbox.id
  route_table_id = aws_route_table.sandbox.id
}

resource "aws_route_table_association" "attacker" {
  subnet_id      = aws_subnet.attacker.id
  route_table_id = aws_route_table.attacker.id
}

# ---------------------------------------------------------------------------
# Security groups — one per subnet role. Each rule below is annotated with
# the exact topology-table row it implements (spec §5).
# ---------------------------------------------------------------------------

resource "aws_security_group" "public_edge" {
  name_prefix = "mirage-${var.environment}-public-edge-"
  description = "Edge-facing broker components: Nginx/HTTP broker, SSH bastion, RD Gateway, VPN."
  vpc_id      = aws_vpc.this.id
  tags        = merge(local.common_tags, { Name = "mirage-${var.environment}-sg-public-edge" })
}

# tfsec ignore below: intentional — this is the one rule in the whole
# topology meant to accept internet traffic (the HTTP broker's public
# showcase endpoint, and/or analyst access — spec section 5, section 6.2
# "HTTP is interception"). var.allowed_analyst_cidr defaults to 0.0.0.0/0
# only in the checked-in dev example tfvars; acceptance/production MUST set
# a real CIDR (enforced by scripts/validate-config's REPLACE_ME_* convention
# on the analogous application-level config, and by code review here).
#tfsec:ignore:aws-ec2-no-public-ingress-sgr
resource "aws_security_group_rule" "public_edge_ingress_https" {
  type              = "ingress"
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
  security_group_id = aws_security_group.public_edge.id
  cidr_blocks       = [var.allowed_analyst_cidr]
  description       = "Analyst browser or VPN to Nginx dashboard and API (topology table row 1)."
}

resource "aws_security_group_rule" "public_edge_ingress_broker_ports" {
  for_each                 = toset([for p in var.broker_backend_ports : tostring(p)])
  type                     = "ingress"
  from_port                = tonumber(each.value)
  to_port                  = tonumber(each.value)
  protocol                 = "tcp"
  security_group_id        = aws_security_group.public_edge.id
  source_security_group_id = aws_security_group.attacker.id
  description              = "Attacker subnet reaches broker entry points ONLY (spec section 5: ATTACKER reaches broker entry points, NOTHING else)."
}

resource "aws_security_group_rule" "public_edge_egress_to_endpoint" {
  type                     = "egress"
  from_port                = 0
  to_port                  = 65535
  protocol                 = "tcp"
  security_group_id        = aws_security_group.public_edge.id
  source_security_group_id = aws_security_group.endpoint.id
  description              = "Broker forwards a selected connection to the ENDPOINT backend (Step 8a /route default target)."
}

resource "aws_security_group_rule" "public_edge_egress_to_sandbox" {
  type                     = "egress"
  from_port                = 0
  to_port                  = 65535
  protocol                 = "tcp"
  security_group_id        = aws_security_group.public_edge.id
  source_security_group_id = aws_security_group.sandbox.id
  description              = "Broker forwards a selected connection to the SANDBOX backend (Step 8a /route sandbox target)."
}

resource "aws_security_group_rule" "public_edge_egress_to_control" {
  type                     = "egress"
  from_port                = 443
  to_port                  = 443
  protocol                 = "tcp"
  security_group_id        = aws_security_group.public_edge.id
  source_security_group_id = aws_security_group.control.id
  description              = "Broker calls mirage-api GET /route before backend establishment (spec section 6.1)."
}

resource "aws_security_group" "control" {
  name_prefix = "mirage-${var.environment}-control-"
  description = "mirage-api, worker, gateway, ingestion, outbox-relay, postgres, nats, elasticsearch, kibana, keycloak, step-ca."
  vpc_id      = aws_vpc.this.id
  tags        = merge(local.common_tags, { Name = "mirage-${var.environment}-sg-control" })
}

resource "aws_security_group_rule" "control_ingress_from_public_edge" {
  type                     = "ingress"
  from_port                = 443
  to_port                  = 443
  protocol                 = "tcp"
  security_group_id        = aws_security_group.control.id
  source_security_group_id = aws_security_group.public_edge.id
  description              = "Broker to mirage-api /route and dashboard/API (topology table)."
}

resource "aws_security_group_rule" "control_ingress_from_endpoint" {
  type                     = "ingress"
  from_port                = 443
  to_port                  = 443
  protocol                 = "tcp"
  security_group_id        = aws_security_group.control.id
  source_security_group_id = aws_security_group.endpoint.id
  description              = "Endpoint/Spider agent to Agent Ingestion, mTLS 443 (topology table)."
}

resource "aws_security_group_rule" "control_ingress_from_endpoint_fleet" {
  type                     = "ingress"
  from_port                = 8220
  to_port                  = 8220
  protocol                 = "tcp"
  security_group_id        = aws_security_group.control.id
  source_security_group_id = aws_security_group.endpoint.id
  description              = "Endpoint Elastic Agent to Fleet Server, 8220 (topology table)."
}

resource "aws_security_group_rule" "control_ingress_from_sandbox" {
  type                     = "ingress"
  from_port                = 443
  to_port                  = 443
  protocol                 = "tcp"
  security_group_id        = aws_security_group.control.id
  source_security_group_id = aws_security_group.sandbox.id
  description              = "Environment Controller to Sandbox Gateway, outbound WSS 443, sandbox DIALS OUT (topology table)."
}

resource "aws_security_group_rule" "control_self_ingress" {
  type              = "ingress"
  from_port         = 0
  to_port           = 65535
  protocol          = "tcp"
  security_group_id = aws_security_group.control.id
  self              = true
  description       = "Control services talk to each other: postgres 5432, nats 4222, elasticsearch 9200 (topology table)."
}

resource "aws_security_group_rule" "control_egress_all_within_vpc" {
  type              = "egress"
  from_port         = 0
  to_port           = 65535
  protocol          = "tcp"
  security_group_id = aws_security_group.control.id
  cidr_blocks       = [var.vpc_cidr]
  description       = "Control-plane egress confined to the VPC (reaches endpoint/sandbox for commands+telemetry, itself for DB/bus)."
}

resource "aws_security_group" "endpoint" {
  name_prefix = "mirage-${var.environment}-endpoint-"
  description = "Windows employee VM (Sysmon, Elastic Agent, MirageEndpoint)."
  vpc_id      = aws_vpc.this.id
  tags        = merge(local.common_tags, { Name = "mirage-${var.environment}-sg-endpoint" })
}

resource "aws_security_group_rule" "endpoint_ingress_from_public_edge" {
  for_each                 = toset([for p in var.broker_backend_ports : tostring(p)])
  type                     = "ingress"
  from_port                = tonumber(each.value)
  to_port                  = tonumber(each.value)
  protocol                 = "tcp"
  security_group_id        = aws_security_group.endpoint.id
  source_security_group_id = aws_security_group.public_edge.id
  description              = "Brokers default target: HTTP/SSH/RDP backend selection (Appendix H)."
}

resource "aws_security_group_rule" "endpoint_egress_to_control" {
  type                     = "egress"
  from_port                = 0
  to_port                  = 65535
  protocol                 = "tcp"
  security_group_id        = aws_security_group.endpoint.id
  source_security_group_id = aws_security_group.control.id
  description              = "Endpoint agent to Agent Ingestion (443) and Fleet Server (8220), agent DIALS the control plane."
}

resource "aws_security_group" "sandbox" {
  name_prefix = "mirage-${var.environment}-sandbox-"
  description = "Windows sandbox VM (Spider, EnvController). Dials OUT only."
  vpc_id      = aws_vpc.this.id
  tags        = merge(local.common_tags, { Name = "mirage-${var.environment}-sg-sandbox" })
}

resource "aws_security_group_rule" "sandbox_ingress_from_public_edge" {
  for_each                 = toset([for p in var.broker_backend_ports : tostring(p)])
  type                     = "ingress"
  from_port                = tonumber(each.value)
  to_port                  = tonumber(each.value)
  protocol                 = "tcp"
  security_group_id        = aws_security_group.sandbox.id
  source_security_group_id = aws_security_group.public_edge.id
  description              = "Brokers approved target after steering: HTTP/SSH/RDP backend selection (Appendix H)."
}

resource "aws_security_group_rule" "sandbox_egress_to_control_only" {
  type                     = "egress"
  from_port                = 443
  to_port                  = 443
  protocol                 = "tcp"
  security_group_id        = aws_security_group.sandbox.id
  source_security_group_id = aws_security_group.control.id
  description              = "Sandbox dials OUT only to explicitly approved control services (Spider to Ingestion mTLS, Controller to Gateway WSS), both 443 (spec section 5, Step 2 rule)."
}

resource "aws_security_group" "attacker" {
  name_prefix = "mirage-${var.environment}-attacker-"
  description = "Kali (or any simulated intruder host). Reaches broker entry points, NOTHING else."
  vpc_id      = aws_vpc.this.id
  tags        = merge(local.common_tags, { Name = "mirage-${var.environment}-sg-attacker" })
}

resource "aws_security_group_rule" "attacker_egress_to_public_edge_only" {
  for_each                 = toset([for p in var.broker_backend_ports : tostring(p)])
  type                     = "egress"
  from_port                = tonumber(each.value)
  to_port                  = tonumber(each.value)
  protocol                 = "tcp"
  security_group_id        = aws_security_group.attacker.id
  source_security_group_id = aws_security_group.public_edge.id
  description              = "Attackers ONLY permitted egress: broker entry points (HTTP/SSH/RDP). No rule anywhere grants attacker access to control, endpoint, sandbox, or evidence."
}

# ---------------------------------------------------------------------------
# VPC Endpoints — S3 (Gateway), KMS + Secrets Manager (Interface), scoped so
# only the control subnet/security-group can reach them. No NAT gateway.
# ---------------------------------------------------------------------------

resource "aws_security_group" "vpc_endpoints" {
  name_prefix = "mirage-${var.environment}-vpce-"
  description = "Interface VPC endpoints (KMS, Secrets Manager) - reachable only from the control security group."
  vpc_id      = aws_vpc.this.id
  tags        = merge(local.common_tags, { Name = "mirage-${var.environment}-sg-vpce" })
}

resource "aws_security_group_rule" "vpce_ingress_from_control" {
  type                     = "ingress"
  from_port                = 443
  to_port                  = 443
  protocol                 = "tcp"
  security_group_id        = aws_security_group.vpc_endpoints.id
  source_security_group_id = aws_security_group.control.id
  description              = "Only control-plane services may call S3/KMS/Secrets Manager (Step 2 rule)."
}

data "aws_region" "current" {}

resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.this.id
  service_name      = "com.amazonaws.${data.aws_region.current.name}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.control.id]

  tags = merge(local.common_tags, { Name = "mirage-${var.environment}-vpce-s3" })
}

resource "aws_vpc_endpoint" "kms" {
  vpc_id              = aws_vpc.this.id
  service_name        = "com.amazonaws.${data.aws_region.current.name}.kms"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = [aws_subnet.control.id]
  security_group_ids  = [aws_security_group.vpc_endpoints.id]
  private_dns_enabled = true

  tags = merge(local.common_tags, { Name = "mirage-${var.environment}-vpce-kms" })
}

resource "aws_vpc_endpoint" "secretsmanager" {
  vpc_id              = aws_vpc.this.id
  service_name        = "com.amazonaws.${data.aws_region.current.name}.secretsmanager"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = [aws_subnet.control.id]
  security_group_ids  = [aws_security_group.vpc_endpoints.id]
  private_dns_enabled = true

  tags = merge(local.common_tags, { Name = "mirage-${var.environment}-vpce-secretsmanager" })
}
