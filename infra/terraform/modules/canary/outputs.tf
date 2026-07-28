output "callback_base_url" {
  value = "https://${var.domain_name}/c"
}
output "lambda_arn" {
  value = aws_lambda_function.collector.arn
}
