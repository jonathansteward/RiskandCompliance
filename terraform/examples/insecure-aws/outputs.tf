output "iam_password_policy_id" {
  value = aws_iam_account_password_policy.noncompliant.id
}

output "cloudtrail_arn" {
  value = aws_cloudtrail.noncompliant.arn
}

output "account_public_access_block_id" {
  value = aws_s3_account_public_access_block.noncompliant.id
}

output "public_read_bucket_id" {
  value = aws_s3_bucket.public_read.id
}

output "public_write_bucket_id" {
  value = aws_s3_bucket.public_write.id
}

output "subnet_id" {
  value = aws_subnet.noncompliant.id
}

output "control_coverage_note" {
  value = "root-account-mfa-enabled (CTRL-001) has no Terraform resource - it is an account-level manual setting, not something these examples can violate via IaC."
}
