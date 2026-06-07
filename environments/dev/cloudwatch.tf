# ============================================================
# CloudWatch Logs Infrastructure
# ============================================================

# ── Infrastructure Log Groups ───────────────────────────────

# VPC Flow Logs
resource "aws_cloudwatch_log_group" "vpc_flow_logs" {
  name              = "/aws/vpc/flowlogs"
  retention_in_days = 7

  tags = {
    Name        = "${local.name_prefix}-vpc-flowlogs"
    Environment = var.env
    ManagedBy   = "Terraform"
  }
}

# CloudTrail Logs
resource "aws_cloudwatch_log_group" "cloudtrail" {
  name              = "/aws/cloudtrail/logs"
  retention_in_days = 7

  tags = {
    Name        = "${local.name_prefix}-cloudtrail-logs"
    Environment = var.env
    ManagedBy   = "Terraform"
  }
}

# ── Web Tier Log Groups ─────────────────────────────────────

# Web Tier - System Logs (messages, secure)
resource "aws_cloudwatch_log_group" "web_system" {
  name              = "/aws/ec2/web-tier/system"
  retention_in_days = 7

  tags = {
    Name        = "${local.name_prefix}-web-system-logs"
    Environment = var.env
    ManagedBy   = "Terraform"
  }
}

# Web Tier - HTTP Server Logs (Apache/Nginx)
resource "aws_cloudwatch_log_group" "web_httpd" {
  name              = "/aws/ec2/web-tier/httpd"
  retention_in_days = 7

  tags = {
    Name        = "${local.name_prefix}-web-httpd-logs"
    Environment = var.env
    ManagedBy   = "Terraform"
  }
}

# Web Tier - PHP Application Logs
resource "aws_cloudwatch_log_group" "web_application" {
  name              = "/aws/ec2/web-tier/application"
  retention_in_days = 14 # Business logs need longer retention

  tags = {
    Name        = "${local.name_prefix}-web-application-logs"
    Environment = var.env
    ManagedBy   = "Terraform"
  }
}

# ── App Tier Log Groups ─────────────────────────────────────

# App Tier - System Logs
resource "aws_cloudwatch_log_group" "app_system" {
  name              = "/aws/ec2/app-tier/system"
  retention_in_days = 7

  tags = {
    Name        = "${local.name_prefix}-app-system-logs"
    Environment = var.env
    ManagedBy   = "Terraform"
  }
}

# App Tier - Streamlit Application Logs
resource "aws_cloudwatch_log_group" "app_streamlit" {
  name              = "/aws/ec2/app-tier/streamlit"
  retention_in_days = 7

  tags = {
    Name        = "${local.name_prefix}-app-streamlit-logs"
    Environment = var.env
    ManagedBy   = "Terraform"
  }
}

# ── Database Log Groups ─────────────────────────────────────

# RDS MySQL - Error Logs
resource "aws_cloudwatch_log_group" "rds_error" {
  name              = "/aws/rds/mysql/error"
  retention_in_days = 7

  tags = {
    Name        = "${local.name_prefix}-rds-error-logs"
    Environment = var.env
    ManagedBy   = "Terraform"
  }
}

# RDS MySQL - Slow Query Logs
resource "aws_cloudwatch_log_group" "rds_slowquery" {
  name              = "/aws/rds/mysql/slowquery"
  retention_in_days = 14 # Performance logs need longer retention

  tags = {
    Name        = "${local.name_prefix}-rds-slowquery-logs"
    Environment = var.env
    ManagedBy   = "Terraform"
  }
}

# ── IAM Role for VPC Flow Logs ─────────────────────────────

resource "aws_iam_role" "flow_logs" {
  name = "${local.name_prefix}-vpc-flow-logs-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "vpc-flow-logs.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = {
    Name = "${local.name_prefix}-vpc-flow-logs-role"
  }
}

resource "aws_iam_role_policy" "flow_logs" {
  name = "${local.name_prefix}-vpc-flow-logs-policy"
  role = aws_iam_role.flow_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogGroups",
          "logs:DescribeLogStreams"
        ]
        Resource = "*"
      }
    ]
  })
}

# ── VPC Flow Logs ───────────────────────────────────────────

resource "aws_flow_log" "main" {
  vpc_id          = aws_vpc.main.id
  traffic_type    = "ALL" # Capture ACCEPT, REJECT, and ALL traffic
  iam_role_arn    = aws_iam_role.flow_logs.arn
  log_destination = aws_cloudwatch_log_group.vpc_flow_logs.arn

  tags = {
    Name        = "${local.name_prefix}-vpc-flow-log"
    Environment = var.env
  }
}

# ── IAM Policy for EC2 to Write CloudWatch Logs ────────────

resource "aws_iam_policy" "cloudwatch_agent_policy" {
  name        = "${local.name_prefix}-cloudwatch-agent-policy"
  description = "Allow EC2 instances to write logs to CloudWatch"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogStreams"
        ]
        Resource = [
          # Web tier log groups
          aws_cloudwatch_log_group.web_system.arn,
          "${aws_cloudwatch_log_group.web_system.arn}:*",
          aws_cloudwatch_log_group.web_httpd.arn,
          "${aws_cloudwatch_log_group.web_httpd.arn}:*",
          aws_cloudwatch_log_group.web_application.arn,
          "${aws_cloudwatch_log_group.web_application.arn}:*",
          # App tier log groups
          aws_cloudwatch_log_group.app_system.arn,
          "${aws_cloudwatch_log_group.app_system.arn}:*",
          aws_cloudwatch_log_group.app_streamlit.arn,
          "${aws_cloudwatch_log_group.app_streamlit.arn}:*",
          # Infrastructure log groups
          aws_cloudwatch_log_group.vpc_flow_logs.arn,
          "${aws_cloudwatch_log_group.vpc_flow_logs.arn}:*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "cloudwatch:PutMetricData"
        ]
        Resource = "*"
      }
    ]
  })

  tags = {
    Name = "${local.name_prefix}-cloudwatch-agent-policy"
  }
}

resource "aws_iam_role_policy_attachment" "cloudwatch_agent_attachment" {
  role       = aws_iam_role.ec2_role.name
  policy_arn = aws_iam_policy.cloudwatch_agent_policy.arn
}

# ── CloudWatch Alarms (Optional - for monitoring) ──────────

# Alarm for high number of rejected connections
resource "aws_cloudwatch_metric_alarm" "vpc_rejected_connections" {
  alarm_name          = "${local.name_prefix}-vpc-high-rejects"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "PacketsDropped"
  namespace           = "AWS/VPC"
  period              = "300"
  statistic           = "Sum"
  threshold           = "100"
  alarm_description   = "Alert when VPC rejects more than 100 packets in 5 minutes"
  treat_missing_data  = "notBreaching"

  dimensions = {
    VpcId = aws_vpc.main.id
  }

  tags = {
    Name        = "${local.name_prefix}-vpc-rejects-alarm"
    Environment = var.env
  }
}

# ── Outputs ─────────────────────────────────────────────────

output "cloudwatch_log_groups" {
  description = "CloudWatch Log Groups created"
  value = {
    # Infrastructure
    vpc_flow_logs = aws_cloudwatch_log_group.vpc_flow_logs.name
    cloudtrail    = aws_cloudwatch_log_group.cloudtrail.name

    # Web Tier
    web_system      = aws_cloudwatch_log_group.web_system.name
    web_httpd       = aws_cloudwatch_log_group.web_httpd.name
    web_application = aws_cloudwatch_log_group.web_application.name

    # App Tier
    app_system    = aws_cloudwatch_log_group.app_system.name
    app_streamlit = aws_cloudwatch_log_group.app_streamlit.name

    # Database
    rds_error     = aws_cloudwatch_log_group.rds_error.name
    rds_slowquery = aws_cloudwatch_log_group.rds_slowquery.name
  }
}
