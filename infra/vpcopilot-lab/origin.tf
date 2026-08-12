# Larkspur Bank origin — Docker host behind the BIG-IP, and the SSM tunnel target.
# Fixed private IP so `vpcopilot bigip-lab create --origin <ip>:<port>` is stable.
resource "aws_instance" "origin" {
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = var.origin_instance_type
  subnet_id              = aws_subnet.external.id
  private_ip             = var.origin_private_ip
  vpc_security_group_ids = [aws_security_group.origin.id]
  iam_instance_profile   = aws_iam_instance_profile.origin.name
  key_name               = aws_key_pair.lab.key_name
  user_data              = file("${path.module}/user_data/origin.sh")

  # Re-bootstrap (replace the box) if the user-data changes.
  user_data_replace_on_change = true

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required" # IMDSv2 only
  }

  root_block_device {
    volume_type           = "gp3"
    volume_size           = 20
    encrypted             = true
    delete_on_termination = true
  }

  tags = {
    Name = "${var.project}-origin"
    Role = "origin" # the Makefile filters stop/start/tunnel targets on this
  }
}
