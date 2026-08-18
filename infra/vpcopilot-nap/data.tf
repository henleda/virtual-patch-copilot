# Reuse the vpcopilot-lab VPC + external subnet (data-sourced by tag) rather than
# building a second VPC — the NGINX box must sit in the same VPC to reach the
# Larkspur origin, and the lab's origin SG already admits app_port from the VPC
# CIDR, so this box reaches Larkspur with no change to the vpcopilot-lab module.
# If these lookups error, the vpcopilot-lab estate isn't up (or was built under a
# different lab_project name) — stand it up first.
data "aws_vpc" "lab" {
  filter {
    name   = "tag:Name"
    values = ["${var.lab_project}-vpc"]
  }
}

data "aws_subnet" "external" {
  vpc_id = data.aws_vpc.lab.id
  filter {
    name   = "tag:Name"
    values = ["${var.lab_project}-external"]
  }
}

# Ubuntu 22.04 (jammy) — a supported platform for NGINX App Protect WAF v4.
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
