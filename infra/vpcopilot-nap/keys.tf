# SSH keypair for the NGINX+NAP box. The vpcopilot Nginx transport (apply/retire)
# SSHes in with this key over the SSM port-forward. The private half stays under
# ./.secrets/ (gitignored) and never enters Terraform state.
resource "aws_key_pair" "nap" {
  key_name   = "${var.project}-key"
  public_key = file(var.ssh_public_key_path)

  tags = { Name = "${var.project}-key" }
}
