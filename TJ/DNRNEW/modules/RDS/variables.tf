variable "region" {
  description = "AWS Deployment region.."
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "The environment this belongs to"
  type        = string
  default     = "dev"
}

variable "rds_engine" {
  description = "RDS Engine name"
  type        = string
  default     = "postgres"
}

variable "engine_version" {
  description = "RDS DB Engine Version"
  type        = string
  default     = "13.1"
}

variable "instance_class" {
  description = "The instance type of the RDS instance"
  type        = string
  default     = "db.t3.micro"
}

variable "storage_type" {
  description = "One of standard (magnetic), gp2 (general purpose SSD), or io1 (provisioned IOPS SSD)"
  type        = string
  default     = "gp2"
}

variable "storage" {
  description = "Allocated Storage"
  type        = string
  default     = "20"
}

variable "max_allocated_storage" {
  type        = string
  description = "The upper limit to which Amazon RDS can automatically scale the storage of the DB instance, 0 to disable Storage Autoscaling."
  default     = "0"
}

variable "db_instance_name" {
  description = "The RDS DB instance Name"
  type        = string
  default     = "dnr-dev-pg"
}

variable "db_name" {
  description = "Name of the DB Instance"
  type        = string
  default     = "postgres"
}

variable "db_user" {
  description = "Username for the DB user"
  type        = string
  default     = "postgres"
}

variable "db_password" {
  description = "Password for the DB user"
  type        = string
  default     = "password1234"
}

variable "port" {
  description = "The port on which the DB accepts connections"
  type        = string
  default     = "5432"
}

variable "final_snapshot_identifier" {
  description = "The RDS DB instance Name"
  type        = string
  default     = "dnr-dev-pg-finalsnapshot"
}
