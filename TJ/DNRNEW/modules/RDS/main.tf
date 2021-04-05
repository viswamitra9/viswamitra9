resource "aws_db_instance" "dnr-dev-rds" {
  identifier = var.db_instance_name

  engine         = var.rds_engine
  engine_version = var.engine_version
  name           = var.db_name
  username       = var.db_user
  password       = var.db_password
  port           = var.port
  instance_class = var.instance_class

  storage_type          = var.storage_type
  max_allocated_storage = var.max_allocated_storage
  allocated_storage     = var.storage

  db_subnet_group_name = aws_db_subnet_group.this.name

  vpc_security_group_ids = [aws_security_group.this.id]

  copy_tags_to_snapshot     = true
  skip_final_snapshot       = true
  final_snapshot_identifier = var.final_snapshot_identifier

  tags = {
    Name        = var.db_name
    environment = var.environment
  }
}