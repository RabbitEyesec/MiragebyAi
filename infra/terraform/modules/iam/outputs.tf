output "control_node_role_arn" {
  value = aws_iam_role.control_node.arn
}

output "control_node_instance_profile_name" {
  value = aws_iam_instance_profile.control_node.name
}

output "policy_arns" {
  value = {
    mirage_api             = aws_iam_policy.mirage_api.arn
    mirage_worker          = aws_iam_policy.mirage_worker.arn
    mirage_outbox_relay    = aws_iam_policy.mirage_outbox_relay.arn
    mirage_agent_ingestion = aws_iam_policy.mirage_agent_ingestion.arn
    mirage_sandbox_gateway = aws_iam_policy.mirage_sandbox_gateway.arn
  }
}
