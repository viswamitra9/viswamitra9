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

resource "aws_athena_database" "demo_db_one" {
  bucket = aws_s3_bucket.demo_bucket2.bucket
  name = "${var.Environment}_demo_db_one" # database name
  encryption_configuration {
    encryption_option = "sse_kms"
    kms_key           = var.kms_key_arn
  }
}

resource "aws_glue_crawler" "demo_crawler_one" {
  database_name = aws_athena_database.demo_db_one.name
  name = "${var.Environment}_crawler"
  role = var.glu_iam_role

  s3_target {
    path = var.glue_s3
  }
}

resource "aws_glue_trigger" "demo_trigger" {
  name = "demo_trigger"
  type = "SCHEDULED"
  enabled = true
  schedule = "cron(0 10 * * 7 *)"
  actions {
    crawler_name = aws_glue_crawler.demo_crawler_one.name
  }
}

/* Likith is taking care of the ETL job so we no need to worry about this script*/

resource "aws_glue_job" "glue_etl" {
  name = "glue_etl"
  role_arn = var.glu_iam_role

  command {
    script_location = var.glu_etl_script
  }
}

resource "aws_glue_trigger" "job_trigger" {
  name = "job_trigger"
  type = "SCHEDULED"
  enabled = true
  schedule = "cron(0 14 * * 7 *)"
  actions {
    job_name = aws_glue_job.glue_etl.name
  }
}