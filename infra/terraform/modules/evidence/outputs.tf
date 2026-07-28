output "bucket_name" {
  value = aws_s3_bucket.evidence.bucket
}

output "bucket_arn" {
  value = aws_s3_bucket.evidence.arn
}

output "signing_key_arn" {
  value = aws_kms_key.signing.arn
}

output "signing_key_alias" {
  value = aws_kms_alias.signing.name
}

output "evidence_encryption_key_arn" {
  value = aws_kms_key.evidence_encryption.arn
}
