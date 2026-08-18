# NGINX + App Protect box SG, in the reused lab VPC. Inbound is minimal: the
# NGINX vhost on :80 (so exploit/legit fire THROUGH the box) and optional direct
# SSH. Management + onboarding ride SSM (no inbound needed). Egress is open for the
# package install (pkgs.nginx.com), the SSM agent, and the origin pool over the VPC.
resource "aws_security_group" "nap" {
  name_prefix = "${var.project}-"
  description = "NGINX+NAP box: HTTP vhost on 80, optional admin SSH; onboarding via SSM."
  vpc_id      = data.aws_vpc.lab.id

  # vhost :80 open to the internet (reached by the copilot; later by XC). Lock to
  # admin_cidrs with allow_public_http=false + allow_admin_to_http instead.
  dynamic "ingress" {
    for_each = var.allow_public_http ? [1] : []
    content {
      description = "NGINX vhost 80 open to the internet (exploit/legit fire through the box)"
      from_port   = 80
      to_port     = 80
      protocol    = "tcp"
      cidr_blocks = ["0.0.0.0/0"]
    }
  }

  dynamic "ingress" {
    for_each = var.allow_admin_to_http ? toset(var.admin_cidrs) : toset([])
    content {
      description = "NGINX vhost 80 from admin ${ingress.value}"
      from_port   = 80
      to_port     = 80
      protocol    = "tcp"
      cidr_blocks = [ingress.value]
    }
  }

  ingress {
    description = "NGINX vhost 80 from within the VPC (verification / around-vs-through checks)"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = [data.aws_vpc.lab.cidr_block]
  }

  dynamic "ingress" {
    for_each = var.allow_admin_to_ssh ? toset(var.admin_cidrs) : toset([])
    content {
      description = "SSH 22 from admin ${ingress.value} (direct; default off — use the SSM tunnel)"
      from_port   = 22
      to_port     = 22
      protocol    = "tcp"
      cidr_blocks = [ingress.value]
    }
  }

  egress {
    description = "all outbound (pkgs.nginx.com install, SSM agent, origin pool over the VPC)"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${var.project}-sg" }
}
