resource "aws_kms_key" "drn_key" {
  description = "KMD key to encrypt all objects"
  key_usage   = ENCRYPT_DECRYPT
  customer_master_key_spec = SYMMETRIC_DEFAULT
}