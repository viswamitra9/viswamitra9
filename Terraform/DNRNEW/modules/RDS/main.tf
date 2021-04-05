resource "random_string" "random" {
  length           = 16
  special          = false
}

resource "aws_db_instance" "dnr-dev-rds" {
  identifier = var.db_instance_name

  engine         = var.rds_engine
  engine_version = var.engine_version
  name           = var.db_name
  username       = var.db_user
  password       = random_string.random.id
  port           = var.port
  instance_class = var.instance_class

  storage_type          = var.storage_type
  max_allocated_storage = var.max_allocated_storage
  allocated_storage     = var.storage

  db_subnet_group_name = var.subnet_group_name

  vpc_security_group_ids = var.security_group_id

  skip_final_snapshot       = true
  backup_retention_period = 0
  apply_immediately = true

  kms_key_id = var.kms_key_id

  multi_az = true

  storage_encrypted = true

  copy_tags_to_snapshot     = true

  tags = {
    environment = var.environment
  }
}
