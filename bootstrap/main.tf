# Block 1 — Terraform config (Pin version provider + binary)
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
  required_version = ">= 1.5.0"
}
# Block 2 — Provider AWS (region Singapore)
provider "aws" {
  region = "ap-southeast-1"
}

# Block 3 — S3 bucket (naming follow convention, prevent_destroy, tags đầy đủ)
resource "aws_s3_bucket" "tfstate" {
  bucket = "p1-bootstrap-apse1-tfstate-240933274359"

  lifecycle {
    prevent_destroy = true
  }
  tags = {
    project  = "p1"
    env      = "bootstrap"
    region   = "apse1"
    resource = "tfstate"
  }
}
# Block 4 — Versioning (Enabled)

resource "aws_s3_bucket_versioning" "version" {
  bucket = aws_s3_bucket.tfstate.id
  versioning_configuration {
    status = "Enabled"
  }
}
# Block 5 — Encryption (AES256)

resource "aws_s3_bucket_server_side_encryption_configuration" "encryption" {
  bucket = aws_s3_bucket.tfstate.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}
# Block 6 — Block public access (4 cái true)
resource "aws_s3_bucket_public_access_block" "public" {
  bucket = aws_s3_bucket.tfstate.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Project     = "project1-layer3"
# Environment = "bootstrap"
# ManagedBy   = "terraform"
# Owner       = "team-layer3"

