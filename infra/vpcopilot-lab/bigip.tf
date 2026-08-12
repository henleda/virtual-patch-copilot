# BIG-IP Advanced WAF VE, two interfaces:
#   eth0 (device_index 0) = management -> mgmt subnet, no public inbound (SSM tunnel)
#   eth1 (device_index 1) = external   -> dataplane subnet, self-IP + VIP secondary
# The public virtual server (443) is built by the copilot's AS3 tenant
# (`vpcopilot bigip-lab create`) after ASM is provisioned and AS3 is installed by
# onboard/bigip-onboard.sh. None of that lands in Terraform state.

resource "aws_network_interface" "bigip_mgmt" {
  subnet_id       = aws_subnet.mgmt.id
  security_groups = [aws_security_group.bigip_mgmt.id]
  description     = "BIG-IP management (eth0)"

  tags = {
    Name = "${var.project}-bigip-mgmt"
  }
}

resource "aws_network_interface" "bigip_external" {
  subnet_id         = aws_subnet.external.id
  security_groups   = [aws_security_group.bigip_external.id]
  source_dest_check = false
  description       = "BIG-IP external/dataplane (eth1): self-IP + VIP secondary IP"

  # [0] primary = the self-IP; [1] secondary = the VIP the Elastic IP maps to.
  private_ip_list_enabled = true
  private_ip_list         = [var.bigip_external_self_ip, var.bigip_vip_ip]

  tags = {
    Name = "${var.project}-bigip-external"
  }
}

resource "aws_instance" "bigip" {
  ami           = local.bigip_ami
  instance_type = var.bigip_instance_type
  key_name      = aws_key_pair.lab.key_name

  network_interface {
    device_index         = 0
    network_interface_id = aws_network_interface.bigip_mgmt.id
  }

  network_interface {
    device_index         = 1
    network_interface_id = aws_network_interface.bigip_external.id
  }

  tags = {
    Name = "${var.project}-bigip"
    Role = "bigip" # the Makefile filters stop/start targets on this
  }
}

# Public VIP Elastic IP -> the external interface's secondary (VIP) private IP.
# The XC origin pool / DNS points here.
resource "aws_eip" "bigip_vip" {
  domain                    = "vpc"
  network_interface         = aws_network_interface.bigip_external.id
  associate_with_private_ip = var.bigip_vip_ip

  tags = {
    Name = "${var.project}-bigip-vip-eip"
  }

  depends_on = [aws_instance.bigip]
}

# Optional management Elastic IP for guaranteed egress (AS3 download, updates).
# Inbound stays closed to the internet via the mgmt SG. Toggle with bigip_mgmt_eip.
resource "aws_eip" "bigip_mgmt" {
  count             = var.bigip_mgmt_eip ? 1 : 0
  domain            = "vpc"
  network_interface = aws_network_interface.bigip_mgmt.id

  tags = {
    Name = "${var.project}-bigip-mgmt-eip"
  }

  depends_on = [aws_instance.bigip]
}
