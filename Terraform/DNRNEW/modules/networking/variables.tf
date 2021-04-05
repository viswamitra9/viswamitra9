variable "vpc_name" {
  description = "Name of VPC"
  type        = string
  default     = "dnr-vpc-dev"
}

variable "vpc_cidr" {
  description = "CIDR block for VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "availability_zones" {
  description = "Availability zones for VPC"
  type        = list(string)
  default     = ["us-east-1a", "us-east-1b",]
}

variable "vpc_tags" {
  description = "Tags to apply to resources created by VPC module"
  type        = map(string)
  default = {
    Name   = "dnr-vpc-dev"
    Environment = "dev"
  }
}

variable "ig_name" {
  description = "Name of Internet Gateway"
  type        = string
  default     = "dnr-ig-dev"
}

variable "nat_name" {
  description = "Name of NAT Gateway"
  type        = string
  default     = "dnr-nat-dev"
}

variable "web_subnet_names" {
  description = "web subnet names"
  type = list(string)
  default = ["dnr-websubnet-1-dev","dnr-websubnet-2-dev"]
}

variable "web_subnets_cidr" {
  description = "public subnet cidr"
  type = list(string)
  default = ["10.0.1.0/24","10.0.2.0/24"]
}

variable "application_subnet_names" {
  description = "application subnet names"
  type = list(string)
  default = ["dnr-appsubnet-1-dev","dnr-appsubnet-2-dev"]
}


variable "application_subnets_cidr" {
  description = "application server subnet cidr"
  type = list(string)
  default = ["10.0.3.0/24","10.0.4.0/24"]
}

variable "database_subnet_names" {
  description = "database subnet names"
  type = list(string)
  default = ["dnr-dbsubnet-1-dev","dnr-dbsubnet-2-dev"]
}

variable "database_subnets_cidr" {
  description = "database server subnet cidr"
  type = list(string)
  default = ["10.0.5.0/24","10.0.6.0/24"]
}

variable "environment" {
  description = "Environment details"
  type = string
  default = "dev"
}

variable "app_routingtable_name" {
  description = "application routing table name"
  type = string
  default = "dnr-approutetable-dev"
}

variable "db_routingtable_name" {
  description = "database routing table name"
  type = string
  default = "dnr-dbroutetable-dev"
}

variable "web_routingtable_name" {
  description = "web routing table name"
  type = string
  default = "dnr-webroutetable-dev"
}

variable "vpc_security_group_name" {
  description = "name of the vpc security group"
  type = string
  default = "dnr-secgroup-dev"
}

variable "db_subnet_name" {
description = "name database subnet group"
type = string
default = "dnr-dbsubnetgroup-dev"
}
