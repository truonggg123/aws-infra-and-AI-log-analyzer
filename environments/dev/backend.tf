terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~>5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~>3.0"
    }
  }
  backend "s3" {
    bucket  = "p1-bootstrap-apse1-tfstate-240933274359"
    key     = "dev/terraform.tfstate"
    region  = "ap-southeast-1"
    encrypt = true

    use_lockfile = true
  }
  required_version = ">= 1.5.0"
}


provider "aws" {
  region = "ap-southeast-1"
  default_tags {
    tags = {
      Environment = "dev"
      Project     = "project1"
      ManagedBy   = "terraform"
    }
  }
}
