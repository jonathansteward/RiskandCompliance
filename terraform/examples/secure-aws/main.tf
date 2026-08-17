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
# control. Root account MFA is enabled manually via the AWS root user login
# (Account settings), not through IAM or any other API-manageable resource.
# See SOP.md for the manual step.

# CTRL-002 / iam-password-policy: strong policy, compliant.
resource "aws_iam_account_password_policy" "compliant" {
  minimum_password_length        = 14
  require_lowercase_characters   = true
  require_uppercase_characters   = true
  require_numbers                = true
  require_symbols                = true
  allow_users_to_change_password = true
  max_password_age               = 90
  password_reuse_prevention      = 24
}

# CTRL-003 / cloudtrail-all-read-s3-data-event-check: trail with an S3 data
# event selector covering all buckets, read-write type "All" (includes reads).
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

resource "aws_cloudtrail" "compliant" {
  name                          = var.cloudtrail_name
  s3_bucket_name                = aws_s3_bucket.cloudtrail_logs.id
  include_global_service_events = true
  is_multi_region_trail         = true

  event_selector {
    read_write_type           = "All"
    include_management_events = true

    data_resource {
      type   = "AWS::S3::Object"
      values = ["arn:aws:s3"]
    }
  }

  depends_on = [aws_s3_bucket_policy.cloudtrail_logs]
}

# CTRL-004 / s3-account-level-public-access-blocks-periodic: all four
# account-level block settings enabled.
#
# NOTE: this resource is a singleton per AWS account/region. Do not apply
# both secure-aws/ and insecure-aws/ against the same account - whichever
# applies last wins, and Terraform state will conflict. See SOP.md.
resource "aws_s3_account_public_access_block" "compliant" {
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# CTRL-005 / CTRL-006 / s3-bucket-public-read-prohibited,
# s3-bucket-public-write-prohibited: private bucket, public access blocked.
resource "aws_s3_bucket" "example" {
  bucket = var.example_bucket_name
}

resource "aws_s3_bucket_ownership_controls" "example" {
  bucket = aws_s3_bucket.example.id
  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

resource "aws_s3_bucket_public_access_block" "example" {
  bucket = aws_s3_bucket.example.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_acl" "example" {
  bucket = aws_s3_bucket.example.id
  acl    = "private"

  depends_on = [aws_s3_bucket_ownership_controls.example]
}

# CTRL-007 / subnet-auto-assign-public-ip-disabled: subnet does not
# auto-assign public IPs to launched instances.
resource "aws_vpc" "example" {
  cidr_block = var.vpc_cidr
}

resource "aws_subnet" "compliant" {
  vpc_id                  = aws_vpc.example.id
  cidr_block              = var.subnet_cidr
  map_public_ip_on_launch = false
}
