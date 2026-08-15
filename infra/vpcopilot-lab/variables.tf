# ---------------------------------------------------------------------------
# vpcopilot-lab — the copilot's own Advanced-WAF BIG-IP lab + Larkspur origin.
# Adapted from nimbus-demo/infra: AWAF (not GOOD) SKU, VPC 10.30.x, management
# reachable ONLY via an SSM port-forward (never public), and no load generators.
# ---------------------------------------------------------------------------

variable "project" {
  description = "Name/tag prefix. All resources carry Project=<this>; the Makefile and `lab-down` scope stop/start to it, so it must be unique to this lab."
  type        = string
  default     = "vpcopilot-lab"
}

variable "aws_profile" {
  description = "AWS CLI/SDK named profile for the NEW account (in ~/.aws/credentials). Replaces the old account's Users-409239147779 profile. Never a raw key."
  type        = string
  default     = "vpcopilot"
}

variable "region" {
  description = "AWS region. Kept at us-east-2 so the F5 Marketplace AMI stays valid."
  type        = string
  default     = "us-east-2"
}

variable "az" {
  description = "Single AZ for the lab (BIG-IP and origin share a zone)."
  type        = string
  default     = "us-east-2a"
}

# --- Network (matches the documented 10.30.x addressing so CLI examples copy-paste) ---

variable "vpc_cidr" {
  description = "CIDR for the lab VPC. Deliberately separate from nimbus-demo's 10.20.0.0/16."
  type        = string
  default     = "10.30.0.0/16"
}

variable "external_subnet_cidr" {
  description = "Dataplane subnet holding the BIG-IP external interface AND the Larkspur origin."
  type        = string
  default     = "10.30.10.0/24"
}

variable "mgmt_subnet_cidr" {
  description = "BIG-IP management subnet (not internet-published; reached via the SSM tunnel)."
  type        = string
  default     = "10.30.20.0/24"
}

variable "origin_private_ip" {
  description = "Fixed private IP of the Larkspur origin. Matches the ROADMAP example so `vpcopilot bigip-lab create --origin 10.30.10.22:8080` still copy-pastes."
  type        = string
  default     = "10.30.10.22"
}

variable "bigip_external_self_ip" {
  description = "BIG-IP external self-IP (primary private IP on eth1). Inside external_subnet_cidr."
  type        = string
  default     = "10.30.10.10"
}

variable "bigip_vip_ip" {
  description = "BIG-IP virtual-server private IP (secondary on eth1). The VIP Elastic IP maps to it; the XC origin pool / `--virtual-address` targets it."
  type        = string
  default     = "10.30.10.190"
}

variable "app_port" {
  description = "Port Larkspur listens on inside the origin (Docker publishes it). The BIG-IP pool forwards here."
  type        = number
  default     = 8080
}

# --- BIG-IP Advanced WAF -----------------------------------------------------

variable "bigip_ami" {
  description = "Explicit BIG-IP Advanced-WAF AMI id. Leave \"\" to auto-resolve the latest matching bigip_ami_name_filter from F5's Marketplace owner. Set explicitly to pin (the ROADMAP lab used ami-0161c65f0d64dff79 = PAYG-Adv WAF Plus 25Mbps in us-east-2)."
  type        = string
  default     = ""
}

variable "bigip_ami_owner" {
  description = "AWS account that owns the F5 Marketplace AMIs."
  type        = string
  default     = "679593333241"
}

variable "bigip_ami_name_filter" {
  description = "Name glob to resolve the AWAF PAYG image. MUST be the Advanced-WAF SKU (has ASM), not GOOD/LTM. Verify the exact name with: aws ec2 describe-images --owners 679593333241 --filters 'Name=name,Values=*Adv WAF*' --query 'Images[].Name'."
  type        = string
  default     = "*PAYG-Adv WAF Plus 25Mbps*"
}

variable "bigip_instance_type" {
  description = "BIG-IP instance type. Advanced WAF + LTM needs >= 8 GiB; m5.xlarge (16 GiB) is the multi-NIC floor."
  type        = string
  default     = "m5.xlarge"
}

variable "bigip_mgmt_eip" {
  description = "Attach an Elastic IP to the BIG-IP management interface for guaranteed egress (AS3 download, updates). Inbound is still closed to the internet by the mgmt SG. Set false to save ~$3.60/mo if PAYG licensing + AS3 install work over the dataplane path in your setup."
  type        = bool
  default     = true
}

# --- Origin ------------------------------------------------------------------

variable "origin_instance_type" {
  description = "Larkspur origin instance type."
  type        = string
  default     = "t3.small"
}

# --- Access ------------------------------------------------------------------

variable "ssh_public_key_path" {
  description = "Public half of the SSH keypair for BIG-IP admin. Private half stays under ./.secrets/ (gitignored) and never enters state. Regenerate on the new laptop: ssh-keygen -t rsa -b 4096 -N '' -f .secrets/vpcopilot_lab.pem."
  type        = string
  default     = "./.secrets/vpcopilot_lab.pub"
}

variable "admin_cidrs" {
  description = "Operator egress CIDRs for OPTIONAL direct testing of the VIP / break-glass mgmt. Empty by default — the tool reaches the VIP through XC and management through the SSM tunnel, so no operator IP is required."
  type        = list(string)
  default     = []
}

variable "xc_re_cidrs" {
  description = "F5 XC Regional Edge egress CIDRs allowed to reach the BIG-IP VIP on 443. Sourced from the KEPT XC tenant (f5-amer-ent / d-henley). Populate so the origin is reachable through XC; leave empty only during bring-up."
  type        = list(string)
  default     = []
}

variable "allow_vpc_to_vip" {
  description = "Allow the VPC CIDR to reach the BIG-IP VIP on 443 (origin-side verification curls)."
  type        = bool
  default     = true
}

variable "allow_public_vip" {
  description = "Open the BIG-IP VIP on 443 to the internet (0.0.0.0/0) so the KEPT XC tenant's Regional Edges reach it with NO RE-IP allowlist to maintain — which is F5's own recommendation (RE ranges change without notice). Lock the origin at L7 instead (an X-Nimbus-Origin-style header check on the appliance, as the nimbus estate does) if you want it private. True is the lab default; xc_re_cidrs stays an optional escape hatch."
  type        = bool
  default     = true
}

variable "allow_admin_to_vip" {
  description = "Allow admin_cidrs to reach the VIP on 443 for direct (non-XC) testing."
  type        = bool
  default     = false
}

variable "allow_admin_to_mgmt" {
  description = "Break-glass: allow admin_cidrs to reach BIG-IP management on 443 directly. Default false — management is reached via the SSM tunnel, not the internet."
  type        = bool
  default     = false
}
