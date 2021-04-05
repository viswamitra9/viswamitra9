output "db_subnet_name" {
  value = aws_db_subnet_group.default.id
}

output "aws_security_group_id" {
value = aws_security_group.default.id
}
