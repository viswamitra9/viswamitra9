resource "aws_s3_bucket" "dnr-glacier-dev" {
  bucket        = var.glacier_name
  acl           = "private"
  force_destroy = "true"

  tags = {
    Environment = var.environment
  }
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        kms_master_key_id = var.kms_master_key_id
        sse_algorithm     = "aws:kms"
      }
    }
  }
}

resource "aws_s3_bucket" "dnr-s3" {
  count         = length(var.s3_buckets_name)
  bucket        = element(var.s3_buckets_name, count.index)
  acl           = "private"
  force_destroy = "true"

  tags = {
    Environment = var.environment
  }
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        kms_master_key_id = var.kms_master_key_id
        sse_algorithm     = "aws:kms"
      }
    }
  }
}