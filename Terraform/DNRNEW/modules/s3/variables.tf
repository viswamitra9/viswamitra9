variable "glacier_name" {
  description = "Name of glacier"
  type        = string
  default     = "dnr-dev-glacier"
}

variable "environment" {
  description = "Environment details"
  type = string
  default = "dev"
}

variable "s3_buckets_name" {
  description = "list of s3 buckets"
  type = list(string)
  default = ["dnr-dev-truesource-sorce","dnr-dev-feasibility","dnr-dev-feasibility-archive"]
}

variable "kms_master_key_id" {
description = "kms key id to encrypt the s3 bucket"
type = string
}
