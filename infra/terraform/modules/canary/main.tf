locals {
  tags = { Project = var.project, Environment = var.environment, Component = "canary-collector" }
}

resource "aws_iam_role" "collector" {
  name = "mirage-${var.environment}-canary-collector"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "lambda.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
  tags = local.tags
}

resource "aws_iam_role_policy" "collector" {
  role = aws_iam_role.collector.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "${aws_cloudwatch_log_group.collector.arn}:*"
      },
      {
        Effect   = "Allow"
        Action   = ["secretsmanager:GetSecretValue"]
        Resource = var.signing_secret_arn
      }
    ]
  })
}

resource "aws_cloudwatch_log_group" "collector" {
  name              = "/aws/lambda/mirage-${var.environment}-canary-collector"
  retention_in_days = var.log_retention_days
  kms_key_id        = null # tfsec:ignore:aws-cloudwatch-log-group-customer-key -- account log key is supplied by environment wrapper in acceptance
  tags              = local.tags
}

resource "aws_lambda_function" "collector" {
  function_name    = "mirage-${var.environment}-canary-collector"
  role             = aws_iam_role.collector.arn
  runtime          = "python3.12"
  handler          = "mirage_canary_collector.handler.handler"
  filename         = var.lambda_zip_path
  source_code_hash = filebase64sha256(var.lambda_zip_path)
  timeout          = 10
  memory_size      = 256
  environment {
    variables = {
      CANARY_SIGNING_SECRET_ARN = var.signing_secret_arn
      CANARY_INGESTION_URL      = var.ingestion_url
    }
  }
  dead_letter_config {
    target_arn = aws_sqs_queue.dlq.arn
  }
  reserved_concurrent_executions = 20
  tags                           = local.tags
}

resource "aws_sqs_queue" "dlq" {
  name                      = "mirage-${var.environment}-canary-dlq"
  message_retention_seconds = 1209600
  kms_master_key_id         = "alias/aws/sqs"
  tags                      = local.tags
}

resource "aws_iam_role_policy" "dlq" {
  role = aws_iam_role.collector.id
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = ["sqs:SendMessage"], Resource = aws_sqs_queue.dlq.arn }]
  })
}

resource "aws_apigatewayv2_api" "collector" {
  name          = "mirage-${var.environment}-canary"
  protocol_type = "HTTP"
  cors_configuration {
    allow_methods = ["GET", "HEAD"]
    allow_origins = []
  }
  tags = local.tags
}

resource "aws_apigatewayv2_integration" "collector" {
  api_id                 = aws_apigatewayv2_api.collector.id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.collector.invoke_arn
  payload_format_version = "2.0"
}

resource "aws_apigatewayv2_route" "callback" {
  api_id    = aws_apigatewayv2_api.collector.id
  route_key = "ANY /c/{token}"
  target    = "integrations/${aws_apigatewayv2_integration.collector.id}"
}

resource "aws_apigatewayv2_stage" "default" {
  api_id      = aws_apigatewayv2_api.collector.id
  name        = "$default"
  auto_deploy = true
  default_route_settings {
    throttling_burst_limit = 100
    throttling_rate_limit  = 50
  }
  access_log_settings {
    destination_arn = aws_cloudwatch_log_group.api.arn
    format          = jsonencode({ requestId = "$context.requestId", sourceIp = "$context.identity.sourceIp", status = "$context.status" })
  }
  tags = local.tags
}

resource "aws_wafv2_web_acl" "collector" {
  name  = "mirage-${var.environment}-canary"
  scope = "REGIONAL"

  default_action {
    allow {}
  }

  rule {
    name     = "per-ip-rate-limit"
    priority = 1
    action {
      block {}
    }
    statement {
      rate_based_statement {
        aggregate_key_type = "IP"
        limit              = var.waf_rate_limit_per_five_minutes
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "mirage-${var.environment}-canary-rate-limit"
      sampled_requests_enabled   = false
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "mirage-${var.environment}-canary"
    sampled_requests_enabled   = false
  }
  tags = local.tags
}

resource "aws_wafv2_web_acl_association" "collector" {
  resource_arn = "arn:aws:apigateway:${data.aws_region.current.name}::/apis/${aws_apigatewayv2_api.collector.id}/stages/${aws_apigatewayv2_stage.default.name}"
  web_acl_arn  = aws_wafv2_web_acl.collector.arn
}

data "aws_region" "current" {}

resource "aws_cloudwatch_log_group" "api" {
  name              = "/aws/apigateway/mirage-${var.environment}-canary"
  retention_in_days = var.log_retention_days
  tags              = local.tags
}

resource "aws_lambda_permission" "api" {
  statement_id  = "AllowApiGateway"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.collector.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.collector.execution_arn}/*/*"
}

resource "aws_apigatewayv2_domain_name" "collector" {
  domain_name = var.domain_name
  domain_name_configuration {
    certificate_arn = var.certificate_arn
    endpoint_type   = "REGIONAL"
    security_policy = "TLS_1_2"
  }
  tags = local.tags
}

resource "aws_apigatewayv2_api_mapping" "collector" {
  api_id      = aws_apigatewayv2_api.collector.id
  domain_name = aws_apigatewayv2_domain_name.collector.id
  stage       = aws_apigatewayv2_stage.default.id
}

resource "aws_route53_record" "collector" {
  zone_id = var.hosted_zone_id
  name    = var.domain_name
  type    = "A"
  alias {
    name                   = aws_apigatewayv2_domain_name.collector.domain_name_configuration[0].target_domain_name
    zone_id                = aws_apigatewayv2_domain_name.collector.domain_name_configuration[0].hosted_zone_id
    evaluate_target_health = false
  }
}
