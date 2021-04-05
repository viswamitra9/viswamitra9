# Create VPC
resource "aws_vpc" "vpc" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true
  tags = var.vpc_tags
}
# Create subnets

# Internet gateway for the public subnet
resource "aws_internet_gateway" "web_internet_gateway" {
  vpc_id = aws_vpc.vpc.id
  tags = {
    Name        = var.ig_name
    Environment = var.environment
  }
}

# Elastic IP for NAT
resource "aws_eip" "nat_eip" {
  vpc        = true
  depends_on = [aws_internet_gateway.web_internet_gateway]
}

# NAT
resource "aws_nat_gateway" "nat" {
  allocation_id = aws_eip.nat_eip.id
  subnet_id     = element(aws_subnet.web_subnet.*.id, 0)
  depends_on    = [aws_internet_gateway.web_internet_gateway]
  tags = {
    Name        = var.nat_name
    Environment = var.environment
  }
}

# public subnet
resource "aws_subnet" "web_subnet" {
  vpc_id                  = aws_vpc.vpc.id
  count                   = length(var.web_subnets_cidr)
  cidr_block              = element(var.web_subnets_cidr,   count.index)
  availability_zone       = element(var.availability_zones,   count.index)
  map_public_ip_on_launch = true
  tags = {
    Name        = element(var.web_subnet_names,   count.index)
    Environment = var.environment
  }
}

# Application subnet

resource "aws_subnet" "application_subnet" {
  vpc_id                  = aws_vpc.vpc.id
  count                   = length(var.application_subnets_cidr)
  cidr_block              = element(var.application_subnets_cidr, count.index)
  availability_zone       = element(var.availability_zones,   count.index)
  map_public_ip_on_launch = false
  tags = {
    Name        = element(var.application_subnet_names,   count.index)
    Environment = var.environment
  }
}

# Database subnet

resource "aws_subnet" "database_subnet" {
  vpc_id                  = aws_vpc.vpc.id
  count                   = length(var.database_subnets_cidr)
  cidr_block              = element(var.database_subnets_cidr, count.index)
  availability_zone       = element(var.availability_zones,   count.index)
  map_public_ip_on_launch = false
  tags = {
    Name        = element(var.database_subnet_names,   count.index)
    Environment = var.environment
  }
}

resource "aws_db_subnet_group" "default" {
  name       =  var.db_subnet_name
  subnet_ids =  aws_subnet.database_subnet.*.id

  tags = {
    Name = "Database subnet group"
  }
}

# routing table for application subnet
resource "aws_route_table" "application_route_table" {
  vpc_id = aws_vpc.vpc.id
  tags = {
    Name        = var.app_routingtable_name
    Environment = var.environment
  }
}

# routing table for database subnet
resource "aws_route_table" "database_route_table" {
  vpc_id = aws_vpc.vpc.id
  tags = {
    Name        = var.db_routingtable_name
    Environment = var.environment
  }
}

# routing table for web
resource "aws_route_table" "web_route_table" {
  vpc_id = aws_vpc.vpc.id
  tags = {
    Name        = var.web_routingtable_name
    Environment = var.environment
  }
}

# route for internet gateway from web servers subnet
resource "aws_route" "web_internet_gateway_route" {
  route_table_id         = aws_route_table.web_route_table.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.web_internet_gateway.id
}

# route for NAT gateway from application servers subnet
resource "aws_route" "application_nat_gateway" {
  route_table_id         = aws_route_table.application_route_table.id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.nat.id
}

# route for NAT gateway from database servers subnet
resource "aws_route" "database_nat_gateway" {
  route_table_id         = aws_route_table.database_route_table.id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.nat.id
}


# routing table associations for web servers
resource "aws_route_table_association" "web_route_association" {
  count          = length(var.web_subnets_cidr)
  subnet_id      = element(aws_subnet.web_subnet.*.id, count.index)
  route_table_id = aws_route_table.web_route_table.id
}

# routing table associations for application servers
resource "aws_route_table_association" "application_route_association" {
  count          = length(var.application_subnets_cidr)
  subnet_id      = element(aws_subnet.application_subnet.*.id, count.index)
  route_table_id = aws_route_table.application_route_table.id
}

# routing table associations for database servers
resource "aws_route_table_association" "database_route_association" {
  count          = length(var.database_subnets_cidr)
  subnet_id      = element(aws_subnet.database_subnet.*.id, count.index)
  route_table_id = aws_route_table.database_route_table.id
}


# ==== VPC's Default Security Group ======

resource "aws_security_group" "default" {
  name        = var.vpc_security_group_name
  description = "Default security group to allow inbound/outbound from the VPC"
  vpc_id      = aws_vpc.vpc.id
  depends_on  = [aws_vpc.vpc]
  ingress {
    from_port = "0"
    to_port   = "0"
    protocol  = "-1"
    self      = true
  }

  egress {
    from_port = "0"
    to_port   = "0"
    protocol  = "-1"
    self      = "true"
  }
  tags = {
    Environment = var.environment
  }
}
