# Run from the operator's laptop under a named AWS profile for the NEW account.
# The profile lives in ~/.aws/credentials — credentials are NEVER placed in this
# repo, in tfvars, or in Terraform state. `terraform.tfvars` sets aws_profile.
provider "aws" {
  region  = var.region
  profile = var.aws_profile

  default_tags {
    tags = {
      Project   = var.project
      ManagedBy = "terraform"
      Context   = "vpcopilot-lab"
    }
  }
}
