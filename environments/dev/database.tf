resource "aws_db_subnet_group" "db" {
  name       = "${local.name_prefix}-db-subnet-group"
  subnet_ids = aws_subnet.db[*].id

  tags = {
    Name = "${local.name_prefix}-db-subnet-group"
  }
}

resource "random_password" "db_password" {
  length           = 16
  special          = true
  override_special = "!#$%"
}

resource "aws_db_instance" "main" {
  identifier     = "${local.name_prefix}-db"
  instance_class = "db.t3.micro"
  engine         = "mysql"
  engine_version = "8.0"
  db_name        = "qlsv_system"
  username       = var.db_username
  password       = random_password.db_password.result

  publicly_accessible    = false
  db_subnet_group_name   = aws_db_subnet_group.db.name
  vpc_security_group_ids = [aws_security_group.db.id]

  allocated_storage = 20
  storage_type      = "gp2"
  # ← THÊM DÒNG NÀY
  enabled_cloudwatch_logs_exports = ["error", "slowquery"]

  skip_final_snapshot = true
  tags = {
    Name        = "${local.name_prefix}-db"
    Environment = var.env
  }
}

output "db_endpoint" {
  value = aws_db_instance.main.address
}

output "db_password" {
  value     = random_password.db_password.result
  sensitive = true
}

# Lưu thông tin bảo mật vào SSM
resource "aws_ssm_parameter" "db_host" {
  name  = "/qlsv/${var.env}/db/host"
  type  = "String"
  value = aws_db_instance.main.address
}

resource "aws_ssm_parameter" "db_user" {
  name  = "/qlsv/${var.env}/db/user"
  type  = "String"
  value = var.db_username
}

resource "aws_ssm_parameter" "db_pass" {
  name  = "/qlsv/${var.env}/db/password"
  type  = "SecureString"
  value = random_password.db_password.result
}

resource "aws_ssm_parameter" "db_name" {
  name  = "/qlsv/${var.env}/db/name"
  type  = "String"
  value = "qlsv_system"
}
