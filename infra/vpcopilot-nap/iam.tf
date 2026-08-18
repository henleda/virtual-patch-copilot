# SSM instance role so the box is an `aws ssm start-session` target — both the SSH
# port-forward's remote end AND the onboarding `send-command` target. No inbound
# SSH rule is required for either.
data "aws_iam_policy_document" "assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "nap" {
  name               = "${var.project}-role"
  assume_role_policy = data.aws_iam_policy_document.assume.json
  tags               = { Name = "${var.project}-role" }
}

resource "aws_iam_role_policy_attachment" "ssm" {
  role       = aws_iam_role.nap.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "nap" {
  name = "${var.project}-profile"
  role = aws_iam_role.nap.name
}
