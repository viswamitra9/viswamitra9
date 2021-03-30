variable "vpc_name" {
  description = "Name of VPC"
  type        = string
  default     = "DNR-"+var.environment+"-VPC"
}

variable "vpc_cidr" {
  description = "CIDR block for VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "vpc_azs" {
  description = "Availability zones for VPC"
  type        = list(string)
  default     = ["us-east-1a", "us-east-1b",]
}

variable "vpc_tags" {
  description = "Tags to apply to resources created by VPC module"
  type        = map(string)
  default = {
    Name   = "DNR-"+var.environment+"-VPC"
    Environment = var.environment
  }
}

variable "environment" {
  description = "Environment details"
  type = string
  default = "dev"
}