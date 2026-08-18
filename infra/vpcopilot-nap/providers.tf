# Run from the operator's laptop under a named AWS profile (SSO). Credentials are
# NEVER placed in this repo, in tfvars, or in Terraform state — only in ~/.aws.
provider "aws" {
  region  = var.region
  profile = var.aws_profile

  default_tags {
    tags = {
      Project   = var.project
      ManagedBy = "terraform"
      Context   = "vpcopilot-nap"
    }
  }
}
