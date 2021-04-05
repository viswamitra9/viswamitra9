resource "aws_kms_key" "drn_key" {
  description = "KMD key to encrypt all objects"
}

resource "aws_kms_alias" "drn_key" {
  name          = "alias/drn-kms-dev"
  target_key_id = aws_kms_key.drn_key.key_id
}
