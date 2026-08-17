output "iam_password_policy_id" {
  value = aws_iam_account_password_policy.compliant.id
}

output "cloudtrail_arn" {
  value = aws_cloudtrail.compliant.arn
}

output "account_public_access_block_id" {
  value = aws_s3_account_public_access_block.compliant.id
}

output "example_bucket_id" {
  value = aws_s3_bucket.example.id
}

output "subnet_id" {
  value = aws_subnet.compliant.id
}

output "control_coverage_note" {
  value = "root-account-mfa-enabled (CTRL-001) has no Terraform resource - it must be enabled manually via the AWS root user login."
}
