# SSH keypair for BIG-IP admin (reached over the SSM tunnel). The private half
# stays under ./.secrets/ (gitignored) and never enters Terraform state. The
# origin uses SSM Session Manager, so it needs no key.
resource "aws_key_pair" "lab" {
  key_name   = "${var.project}-key"
  public_key = file(var.ssh_public_key_path)

  tags = {
    Name = "${var.project}-key"
  }
}
