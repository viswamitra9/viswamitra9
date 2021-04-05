resource "aws_s3_bucket" "dnr-glacier-dev" {
  source = "../../modules/KMS"
  bucket        = glacier_name
  acl           = "private"
  force_destroy = "true"
  storage_class = DEEP_ARCHIVE

  tags = {
    Environment = var.environment
  }
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        kms_master_key_id = module.KMS.arn
        sse_algorithm     = "aws:kms"
      }
    }
  }
}

resource "aws_s3_bucket" "dnr-s3" {
  source = "../../modules/KMS"
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
        kms_master_key_id = module.KMS.arn
        sse_algorithm     = "aws:kms"
      }
    }
  }
}