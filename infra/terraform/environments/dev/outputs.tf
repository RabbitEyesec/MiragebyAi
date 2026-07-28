output "vpc_id" {
  value = module.vpc.vpc_id
}

output "subnet_ids" {
  value = module.vpc.subnet_ids
}

output "security_group_ids" {
  value = module.vpc.security_group_ids
}

output "evidence_bucket_name" {
  value = module.evidence.bucket_name
}

output "signing_key_arn" {
  value = module.evidence.signing_key_arn
}

output "control_node_instance_profile_name" {
  value = module.iam.control_node_instance_profile_name
}

output "canary_callback_base_url" {
  value = var.enable_canary ? module.canary[0].callback_base_url : null
}

output "compute_instance_ids" {
  value = var.enable_compute ? module.compute[0].instance_ids : null
}

output "compute_broker_public_ip" {
  value = var.enable_compute ? module.compute[0].broker_public_ip : null
}
