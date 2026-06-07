data "aws_availability_zones" "available" {
  state = "available"
}

data "aws_caller_identity" "current" {}

variable "tags" {
  description = "Additional tags to merge"
  type        = map(string)
  default     = {}
}

locals {
  account_id  = data.aws_caller_identity.current.account_id
  name_prefix = "${var.project}-${var.env}-${var.region_short}"
  ports       = { http = 80, https = 443, app = 80, db = 3306 }

  azs = data.aws_availability_zones.available.names
}

