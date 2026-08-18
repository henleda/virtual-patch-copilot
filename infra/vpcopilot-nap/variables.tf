# ---------------------------------------------------------------------------
# vpcopilot-nap — the copilot's own F5 WAF for NGINX (App Protect v4) box.
# A single NGINX Plus + App Protect instance that fronts the EXISTING Larkspur
# origin in the vpcopilot-lab VPC, so a finding's declarative band-aid can be
# applied + validated on a real NAP box (the L2 analogue of the BIG-IP lab).
# Reuses the lab VPC/subnet (data-sourced by tag) + the running Larkspur origin;
# the origin SG already admits :app_port from the whole VPC CIDR, so this box
# reaches Larkspur with NO change to the vpcopilot-lab module.
# ---------------------------------------------------------------------------

variable "project" {
  description = "Name/tag prefix. All resources carry Project=<this>; the Makefile scopes stop/start to it, so it must be unique to this box."
  type        = string
  default     = "vpcopilot-nap"
}

variable "aws_profile" {
  description = "AWS CLI/SDK named profile (an SSO profile in ~/.aws/config). Never a raw key."
  type        = string
  default     = "vpcopilot"
}

variable "region" {
  description = "AWS region. us-east-2 to match the vpcopilot-lab VPC this box reuses."
  type        = string
  default     = "us-east-2"
}

variable "az" {
  description = "AZ for the box. Must match the lab external subnet's AZ."
  type        = string
  default     = "us-east-2a"
}

variable "lab_project" {
  description = "Project tag of the vpcopilot-lab estate whose VPC + external subnet this box joins (data-sourced by tag). Change only if the lab was built under a different name."
  type        = string
  default     = "vpcopilot-lab"
}

variable "nap_private_ip" {
  description = "Fixed private IP for the NGINX+NAP box in the lab external subnet (10.30.10.0/24). Distinct from the origin (.22), BIG-IP self-IP (.10) and VIP (.190)."
  type        = string
  default     = "10.30.10.30"
}

variable "origin_private_ip" {
  description = "Larkspur origin private IP the NGINX vhost reverse-proxies to. Matches the vpcopilot-lab default so onboarding copy-pastes."
  type        = string
  default     = "10.30.10.22"
}

variable "app_port" {
  description = "Port Larkspur listens on at the origin. The NGINX proxy_pass upstream port."
  type        = number
  default     = 8080
}

variable "instance_type" {
  description = "NGINX+NAP instance type. App Protect's compiler + enforcer want >= 4 GiB; t3.medium (4 GiB) is the lab floor."
  type        = string
  default     = "t3.medium"
}

variable "root_volume_size" {
  description = "Root EBS size (GiB). NAP packages + attack signatures + compiled policies need headroom."
  type        = number
  default     = 30
}

variable "ssh_public_key_path" {
  description = "Public half of the SSH keypair. Private half stays under ./.secrets/ (gitignored), never in state. Generate: ssh-keygen -t rsa -b 4096 -N '' -f .secrets/vpcopilot_nap.pem && mv .secrets/vpcopilot_nap.pem.pub .secrets/vpcopilot_nap.pub"
  type        = string
  default     = "./.secrets/vpcopilot_nap.pub"
}

variable "admin_cidrs" {
  description = "Operator egress CIDRs for direct testing of the NGINX vhost (:80) and optional public SSH. Empty by default — the box is reached via the SSM tunnel and (by default) a public HTTP rule."
  type        = list(string)
  default     = []
}

variable "allow_public_http" {
  description = "Open the NGINX vhost :80 to the internet (0.0.0.0/0) so the copilot (and later XC) can fire exploit/legit THROUGH the box. True is the lab default; set false + allow_admin_to_http to lock it to admin_cidrs."
  type        = bool
  default     = true
}

variable "allow_admin_to_http" {
  description = "Allow admin_cidrs to reach the NGINX vhost :80 (used when allow_public_http = false)."
  type        = bool
  default     = false
}

variable "allow_admin_to_ssh" {
  description = "Open :22 to admin_cidrs for direct SSH. Default false — SSH rides the SSM port-forward (make tunnel), so no public SSH is required."
  type        = bool
  default     = false
}
