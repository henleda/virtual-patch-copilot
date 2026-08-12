# --- Origin SG: Larkspur is reachable ONLY through the BIG-IP + from within the
#     VPC. Never internet-published, or the "exploit stops at the appliance" demo
#     breaks. Egress open for docker pull and the SSM agent.
resource "aws_security_group" "origin" {
  name_prefix = "${var.project}-origin-"
  description = "Larkspur origin: app port from the BIG-IP and the VPC only."
  vpc_id      = aws_vpc.lab.id

  ingress {
    description     = "app port from the BIG-IP external SG"
    from_port       = var.app_port
    to_port         = var.app_port
    protocol        = "tcp"
    security_groups = [aws_security_group.bigip_external.id]
  }

  ingress {
    description = "app port from within the VPC (verification)"
    from_port   = var.app_port
    to_port     = var.app_port
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }

  egress {
    description = "all outbound (docker pull, SSM agent)"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${var.project}-origin-sg" }
}

# --- BIG-IP external SG: fronts the public virtual server on 443. Reachable from
#     the XC Regional Edge ranges (the kept tenant), optionally the VPC and admin.
resource "aws_security_group" "bigip_external" {
  name_prefix = "${var.project}-bigip-ext-"
  description = "BIG-IP external/dataplane: HTTPS to the public virtual server."
  vpc_id      = aws_vpc.lab.id

  dynamic "ingress" {
    for_each = toset(var.xc_re_cidrs)
    content {
      description = "VIP 443 from XC Regional Edge ${ingress.value}"
      from_port   = 443
      to_port     = 443
      protocol    = "tcp"
      cidr_blocks = [ingress.value]
    }
  }

  dynamic "ingress" {
    for_each = var.allow_admin_to_vip ? toset(var.admin_cidrs) : toset([])
    content {
      description = "VIP 443 from admin ${ingress.value} (direct testing)"
      from_port   = 443
      to_port     = 443
      protocol    = "tcp"
      cidr_blocks = [ingress.value]
    }
  }

  dynamic "ingress" {
    for_each = var.allow_vpc_to_vip ? [1] : []
    content {
      description = "VIP 443 from within the VPC (verification)"
      from_port   = 443
      to_port     = 443
      protocol    = "tcp"
      cidr_blocks = [var.vpc_cidr]
    }
  }

  # Origin-open: XC Regional Edges reach the VIP here without an RE-IP allowlist
  # (F5's recommendation). Lock at L7 with a header check on the appliance if needed.
  dynamic "ingress" {
    for_each = var.allow_public_vip ? [1] : []
    content {
      description = "VIP 443 open to the internet (reached via XC; lock the origin at L7 if required)"
      from_port   = 443
      to_port     = 443
      protocol    = "tcp"
      cidr_blocks = ["0.0.0.0/0"]
    }
  }

  egress {
    description = "all outbound (origin pool over the VPC, plus internet)"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${var.project}-bigip-external-sg" }
}

# --- BIG-IP management SG: NOT internet-published. Inbound only from within the
#     VPC (the origin host, which is the SSM port-forward's near end). An optional
#     break-glass admin rule is off by default.
resource "aws_security_group" "bigip_mgmt" {
  name_prefix = "${var.project}-bigip-mgmt-"
  description = "BIG-IP management: reachable from within the VPC (SSM tunnel) only."
  vpc_id      = aws_vpc.lab.id

  ingress {
    description = "mgmt 443 from within the VPC (SSM tunnel origin)"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }

  ingress {
    description = "mgmt 22 from within the VPC (SSM tunnel origin)"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }

  dynamic "ingress" {
    for_each = var.allow_admin_to_mgmt ? toset(var.admin_cidrs) : toset([])
    content {
      description = "mgmt 443 break-glass from admin ${ingress.value}"
      from_port   = 443
      to_port     = 443
      protocol    = "tcp"
      cidr_blocks = [ingress.value]
    }
  }

  egress {
    description = "all outbound (AS3 download, updates, licensing)"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${var.project}-bigip-mgmt-sg" }
}
