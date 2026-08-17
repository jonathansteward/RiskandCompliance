variable "aws_region" {
  description = "AWS region to deploy example resources into"
  type        = string
  default     = "us-east-2"
}

variable "cloudtrail_bucket_name" {
  description = "Globally-unique S3 bucket name for CloudTrail log storage"
  type        = string
}

variable "cloudtrail_name" {
  description = "Name for the CloudTrail trail"
  type        = string
  default     = "compliant-example-trail"
}

variable "example_bucket_name" {
  description = "Globally-unique S3 bucket name for the general-purpose example bucket"
  type        = string
}

variable "vpc_cidr" {
  description = "CIDR block for the example VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "subnet_cidr" {
  description = "CIDR block for the example subnet"
  type        = string
  default     = "10.0.1.0/24"
}
