terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

# CTRL-001 / root-account-mfa-enabled: no Terraform resource exists for this
# control, so it can't be violated via IaC either. See secure-aws/main.tf.

# CTRL-002 / iam-password-policy: weak policy, non-compliant.
resource "aws_iam_account_password_policy" "noncompliant" {
  minimum_password_length        = 6
  require_lowercase_characters   = false
  require_uppercase_characters   = false
  require_numbers                = false
  require_symbols                = false
  allow_users_to_change_password = true
  max_password_age               = 0
  password_reuse_prevention      = 0
}

# CTRL-003 / cloudtrail-all-read-s3-data-event-check: trail with no S3 data
# event selector at all, so S3 read events are never logged.
resource "aws_s3_bucket" "cloudtrail_logs" {
  bucket = var.cloudtrail_bucket_name
}

data "aws_iam_policy_document" "cloudtrail_bucket_policy" {
  statement {
    sid    = "AWSCloudTrailAclCheck"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.cloudtrail_logs.arn]
  }

  statement {
    sid    = "AWSCloudTrailWrite"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.cloudtrail_logs.arn}/*"]

    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }
}

resource "aws_s3_bucket_policy" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id
  policy = data.aws_iam_policy_document.cloudtrail_bucket_policy.json
}

resource "aws_cloudtrail" "noncompliant" {
  name                          = var.cloudtrail_name
  s3_bucket_name                = aws_s3_bucket.cloudtrail_logs.id
  include_global_service_events = true
  is_multi_region_trail         = false
  # No event_selector block -> S3 data events (including reads) are not
  # logged, which is exactly what cloudtrail-all-read-s3-data-event-check
  # flags as NON_COMPLIANT.

  depends_on = [aws_s3_bucket_policy.cloudtrail_logs]
}

# CTRL-004 / s3-account-level-public-access-blocks-periodic: all four
# account-level block settings disabled.
#
# NOTE: this resource is a singleton per AWS account/region. Do not apply
# both secure-aws/ and insecure-aws/ against the same account - whichever
# applies last wins, and Terraform state will conflict. See SOP.md.
resource "aws_s3_account_public_access_block" "noncompliant" {
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

# CTRL-005 / s3-bucket-public-read-prohibited: bucket ACL allows public read.
resource "aws_s3_bucket" "public_read" {
  bucket = var.public_read_bucket_name
}

resource "aws_s3_bucket_ownership_controls" "public_read" {
  bucket = aws_s3_bucket.public_read.id
  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

resource "aws_s3_bucket_public_access_block" "public_read" {
  bucket = aws_s3_bucket.public_read.id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_s3_bucket_acl" "public_read" {
  bucket = aws_s3_bucket.public_read.id
  acl    = "public-read"

  depends_on = [
    aws_s3_bucket_ownership_controls.public_read,
    aws_s3_bucket_public_access_block.public_read,
  ]
}

# CTRL-006 / s3-bucket-public-write-prohibited: bucket ACL allows public
# read-write.
resource "aws_s3_bucket" "public_write" {
  bucket = var.public_write_bucket_name
}

resource "aws_s3_bucket_ownership_controls" "public_write" {
  bucket = aws_s3_bucket.public_write.id
  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

resource "aws_s3_bucket_public_access_block" "public_write" {
  bucket = aws_s3_bucket.public_write.id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_s3_bucket_acl" "public_write" {
  bucket = aws_s3_bucket.public_write.id
  acl    = "public-read-write"

  depends_on = [
    aws_s3_bucket_ownership_controls.public_write,
    aws_s3_bucket_public_access_block.public_write,
  ]
}

# CTRL-007 / subnet-auto-assign-public-ip-disabled: subnet auto-assigns
# public IPs to launched instances.
resource "aws_vpc" "example" {
  cidr_block = var.vpc_cidr
}

resource "aws_subnet" "noncompliant" {
  vpc_id                  = aws_vpc.example.id
  cidr_block              = var.subnet_cidr
  map_public_ip_on_launch = true
}
