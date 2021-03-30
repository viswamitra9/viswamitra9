variable "athena_s3" {
  type        = string
  description = "Location to store the query results"
  default     = "s3://archivetestcslifesci/request2/"
}

variable "aws_athena_database" {
  type        = string
  description = "database name"
}

variable "kms_key_arn" {
  type        = string
  description = "KMS key ARN used to encrypt the S3 bucket"
}

variable "tags" {
  type = object({
    Name : string
    Environment : string
  })
  description = "tags for athena"
}

variable "glue_s3" {
  type        = string
  description = "Location to store the query results"
  default     = "s3://oa-ls-lsdw-dataq"
}

variable "Environment" {
  type = string
  description = "Environment name"
  default = "nprd"
}

variable "account_id" {
  type = number
  description = "Account id of AWS"
  default = 526621796011
}

variable "redshift_cluster_size" {
  type = string
  description = "cluster size for aws redshift cluster"
  default = "dc2.large"
}

variable "redshift_number_nodes" {
  type = number
  description = "redshift cluster size"
  default = 2
}

variable "redshift_iam_roles" {
  type = list(string)
  description = "redshift IAM roles"
  default = ["arn:aws:iam::526621796011:role/RedshiftSpectrum"]
}

variable "redshift_database_name" {
  type = string
  description = "default database name of redshift"
  default = "dev"
}

variable "redshift_user" {
  type = string
  description = "database username"
  default = "awsuser"
}

variable "glu_iam_role" {
  type = string
  default = "arn:aws:iam:526621796011:role/service-role/AWSGlueServiceRole-DefaultRole"
  description = "glue IAM role"
}

variable "glu_etl_script" {
  type = string
  default = "s3://ls-lsdw-glue-scripts/sparkjob.py"
  description = "glu etl script"
}

variable "redshift_vpc_securitygroups" {
  type = list
  description = "vpc security groups for the cluster"
  default = ["default"]
}