output "vpc_id" {
  value = aws_vpc.this.id
}

output "subnet_ids" {
  value = {
    public_edge = aws_subnet.public_edge.id
    control     = aws_subnet.control.id
    endpoint    = aws_subnet.endpoint.id
    sandbox     = aws_subnet.sandbox.id
    attacker    = aws_subnet.attacker.id
  }
}

output "security_group_ids" {
  value = {
    public_edge   = aws_security_group.public_edge.id
    control       = aws_security_group.control.id
    endpoint      = aws_security_group.endpoint.id
    sandbox       = aws_security_group.sandbox.id
    attacker      = aws_security_group.attacker.id
    vpc_endpoints = aws_security_group.vpc_endpoints.id
  }
}

output "route_table_ids" {
  value = {
    public_edge = aws_route_table.public_edge.id
    control     = aws_route_table.control.id
    endpoint    = aws_route_table.endpoint.id
    sandbox     = aws_route_table.sandbox.id
    attacker    = aws_route_table.attacker.id
  }
}
