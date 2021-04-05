resource "aws_athena_workgroup" "lsdw_athena" {
  name = "${var.Environment}_lsdw_athena"

  configuration {

    result_configuration {
    output_location = var.athena_s3
    encryption_configuration {
      encryption_option = "SSE_KMS"
      kms_key_arn       = var.kms_key_arn
      }
    }
  }

  tags = var.tags
}
