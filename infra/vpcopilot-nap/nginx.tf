# The NGINX Plus + App Protect (v4) box. Single interface in the reused lab
# external subnet, fixed private IP, a public EIP for a stable SSH/HTTP address.
# NAP is NOT installed here — onboarding is out-of-band over SSM (onboard/
# nap-onboard.sh), so the JWT license never lands in user_data or Terraform state.
resource "aws_instance" "nap" {
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = var.instance_type
  subnet_id              = data.aws_subnet.external.id
  private_ip             = var.nap_private_ip
  vpc_security_group_ids = [aws_security_group.nap.id]
  iam_instance_profile   = aws_iam_instance_profile.nap.name
  key_name               = aws_key_pair.nap.key_name
  user_data              = file("${path.module}/user_data/nginx.sh")

  # Re-bootstrap (replace the box) if the user-data changes.
  user_data_replace_on_change = true

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required" # IMDSv2 only
  }

  root_block_device {
    volume_type           = "gp3"
    volume_size           = var.root_volume_size
    encrypted             = true
    delete_on_termination = true
  }

  tags = {
    Name = "${var.project}-box"
    Role = "nap" # the Makefile scopes stop/start/tunnel targets on this
  }
}

# Public Elastic IP -> a stable address for SSH (over the SSM tunnel this is not
# strictly needed, but keeps the HTTP vhost address stable for the --url and a
# future XC re-point). The external subnet auto-assigns a public IP; the EIP
# replaces it with one that survives stop/start.
resource "aws_eip" "nap" {
  domain   = "vpc"
  instance = aws_instance.nap.id
  tags     = { Name = "${var.project}-eip" }

  depends_on = [aws_instance.nap]
}
