resource "aws_lb" "alb" {
	name               = "${local.name_prefix}-alb"
	internal           = false
	load_balancer_type = "application"
	security_groups    = [aws_security_group.alb.id]
	subnets            = [for subnet in aws_subnet.public : subnet.id]

	enable_deletion_protection = false

	tags = {
		Name = "${local.name_prefix}-alb"
	}
}

resource "aws_lb_listener" "app" {
	load_balancer_arn = aws_lb.alb.arn
	port = local.ports.http
	protocol = "HTTP"

	# Forward ALL traffic to web app — only 1 target group
	default_action {
		type             = "forward"
		target_group_arn = aws_lb_target_group.qlsv.arn
	}
}

# ── Target Group cho Web App QLSV (Port 8080) ────────────────────────
resource "aws_lb_target_group" "qlsv" {
	name_prefix     = "qlsv-"
	port     = 8080
	protocol = "HTTP"
	target_type = "instance"
	vpc_id   = aws_vpc.main.id

	health_check {
		enabled             = true
		healthy_threshold   = 3
		interval            = 30
		matcher             = "200-399"
		path                = "/"
		port                = "traffic-port"
		protocol            = "HTTP"
		timeout             = 10
		unhealthy_threshold = 5
	}

	lifecycle {
		create_before_destroy = true
	}

	tags = {
		Name = "${local.name_prefix}-tg-qlsv"
	}
}
