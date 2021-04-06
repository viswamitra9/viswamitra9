output "db_subnet_name" {
  value = aws_db_subnet_group.default.id
}

output "subnet_id" {
  value = aws_subnet.application_subnet.*.id
}

output "aws_security_group_id" {
value = aws_security_group.default.id
}

