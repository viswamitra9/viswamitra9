# Following code will create the redshift cluster
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/redshift_cluster

resource "random_string" "random" {
  length           = 16
  special          = true
  override_special = "/@£$"
}

resource "aws_redshift_cluster" "ls-test-redshift" {
  cluster_identifier     = "ls-${var.Environment}-redshift"
  database_name          = var.redshift_database_name
  node_type              = var.redshift_cluster_size
  cluster_type           = "multi-node"
  master_username        = var.redshift_user
  master_password        = random_string.random.result
  vpc_security_group_ids = var.redshift_vpc_securitygroups
  allow_version_upgrade  = false
  number_of_nodes        = var.redshift_cluster_size
  publicly_accessible    = false
  encrypted              = true
  kms_key_id             = var.kms_key_arn
  skip_final_snapshot    = true
  iam_roles              = var.redshift_iam_roles
  tags                   = var.tags
}

output "cluster_password" {
  value = random_string.random.result
}