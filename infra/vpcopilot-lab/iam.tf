# The origin carries an SSM instance role so it can be an `aws ssm start-session`
# target — it is both the shell host and the near end of the BIG-IP mgmt tunnel.
# No inbound SSH rule is ever needed.
data "aws_iam_policy_document" "assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "origin" {
  name               = "${var.project}-origin-role"
  assume_role_policy = data.aws_iam_policy_document.assume.json

  tags = {
    Name = "${var.project}-origin-role"
  }
}

resource "aws_iam_role_policy_attachment" "ssm" {
  role       = aws_iam_role.origin.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "origin" {
  name = "${var.project}-origin-profile"
  role = aws_iam_role.origin.name
}
