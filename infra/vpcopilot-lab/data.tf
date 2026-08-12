# Ubuntu 22.04 for the Larkspur origin (Docker host + SSM tunnel target).
data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"] # Canonical

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]
  }
  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
  filter {
    name   = "architecture"
    values = ["x86_64"]
  }
}

# Resolve the F5 Advanced-WAF PAYG image ONLY when bigip_ami is not pinned. Gating
# with count means a stale/unsubscribed name filter can't error a plan that pins
# the AMI explicitly. If the filter matches nothing, the plan fails loudly (better
# than silently landing on the wrong SKU) — usually it means the AWAF Marketplace
# subscription isn't accepted in this account yet.
data "aws_ami" "bigip" {
  count       = var.bigip_ami == "" ? 1 : 0
  most_recent = true
  owners      = [var.bigip_ami_owner]

  filter {
    name   = "name"
    values = [var.bigip_ami_name_filter]
  }
  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
  filter {
    name   = "architecture"
    values = ["x86_64"]
  }
}

locals {
  bigip_ami = var.bigip_ami != "" ? var.bigip_ami : data.aws_ami.bigip[0].id
}
