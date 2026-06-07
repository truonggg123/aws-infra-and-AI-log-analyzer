resource "aws_s3_bucket" "ansible_ssm_temp" {
  bucket = "${local.name_prefix}-ansible-ssm-temp-${local.account_id}"

  force_destroy = true

  tags = {
    Name        = "${local.name_prefix}-ansible-ssm-temp"
    Project     = var.project
    Environment = var.env
    Purpose     = "ansible-ssm-temp"
  }

  lifecycle {
    prevent_destroy = false
  }
}

resource "aws_s3_bucket_versioning" "ansible_ssm_temp" {
  bucket = aws_s3_bucket.ansible_ssm_temp.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "ansible_ssm_temp" {
  bucket = aws_s3_bucket.ansible_ssm_temp.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "ansible_ssm_temp" {
  bucket = aws_s3_bucket.ansible_ssm_temp.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "ansible_ssm_temp" {
  bucket = aws_s3_bucket.ansible_ssm_temp.id

  rule {
    id     = "expire-temp-objects"
    status = "Enabled"

    filter {
      prefix = ""
    }

    expiration {
      days = 3
    }

    noncurrent_version_expiration {
      noncurrent_days = 3
    }
  }
}
