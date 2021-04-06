variable "environment" {
  description = "AWS Environment.."
  type        = string
  default     = "dev"
}

variable "ami_id" {
  description = "AMI ID of Instance .."
  type        = string
  default = "ami-07817f5d0e3866d32"
}

variable "win_user" {
  description = "Username of pentaho instance"
  type        = string
  default = "pentaho_user"
}

variable "win_password" {
  description = "Password of pentaho instance"
  type        = string
  default = "Pentaho#1234"
}

variable "instance_type" {
  description = "Type of Instance"
  type        = string
  default     = "t2.micro"
}

variable "instance_name" {
  description = "Name of Instance"
  type        = string
  default = "pentaho-windows"

}

variable "key_name" {
  description = "Name of Instance key"
  type        = string
  default = "pentaho-key"
}

variable "subnet_id" {
  description = "Name (id) of subnet"
  type        = list(string)
}

variable "security_group_id" {
  description = "security group id"
  type = "string"
}