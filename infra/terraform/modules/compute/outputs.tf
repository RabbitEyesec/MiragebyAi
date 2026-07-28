output "instance_ids" {
  value = {
    broker   = aws_instance.broker.id
    control  = aws_instance.control.id
    endpoint = aws_instance.endpoint.id
    sandbox  = aws_instance.sandbox.id
    attacker = aws_instance.attacker.id
  }
}

output "private_ips" {
  value = {
    broker   = aws_instance.broker.private_ip
    control  = aws_instance.control.private_ip
    endpoint = aws_instance.endpoint.private_ip
    sandbox  = aws_instance.sandbox.private_ip
    attacker = aws_instance.attacker.private_ip
  }
}

output "broker_public_ip" {
  value = aws_instance.broker.public_ip
}
