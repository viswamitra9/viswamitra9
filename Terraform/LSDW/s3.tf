resource "aws_s3_bucket" "demo_bucket2" {
  # s3 bucket names must be globally unique
  # prefix them with your AWS account ID
  bucket = "${var.account_id}-ls-lsdw-catalog-db2-${var.Environment}"

  # EIS policy
  # http://cloud.optum.com/docs/launchpad/aws-policies/AWS_S3_bucket_do_not_have_server_side_encryption_-UHG
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm     = "aws:kms"
        kms_master_key_id = var.kms_key_arn
      }
    }
  }

  versioning {
    enabled    = true
    mfa_delete = false
  }

  tags = var.tags
  # put the correct policy in policy.json file and enable the comment
  # policy = file("policy.json")
  force_destroy = false
}