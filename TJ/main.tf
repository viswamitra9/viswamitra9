provider "aws" {
  profile = "saml"
  region = "us-east-1"
  shared_credentials_file = "/home/jenkins/.aws/credentials"
  version = "~> 2.31"
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# store your TF state file on AWS
# IMPORTANT: assumes -terraform-state bucket exists! Create that manually via AWS CLI in your pipeline
terraform {
  backend "s3" {
    bucket  = "526621796011-demo-cstwo"
    key     = "526621796011-demo-cstwo.tfstate"
    region  = "us-east-1"
    profile = "saml"
  }

  required_version = ">= 0.12.0"
}