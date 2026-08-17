output "vpc_id" {
  description = "The lab VPC id."
  value       = aws_vpc.lab.id
}

output "origin_instance_id" {
  description = "Larkspur origin EC2 id — the SSM tunnel target and `make origin-deploy`/`origin-shell` target."
  value       = aws_instance.origin.id
}

output "origin_private_ip" {
  description = "Larkspur origin private IP — the BIG-IP pool member / `bigip-lab create --origin`."
  value       = aws_instance.origin.private_ip
}

output "bigip_instance_id" {
  description = "BIG-IP EC2 id."
  value       = aws_instance.bigip.id
}

output "bigip_ami_used" {
  description = "The AMI the BIG-IP launched from (pinned var or the resolved AWAF Marketplace image)."
  value       = local.bigip_ami
}

output "bigip_vip_eip" {
  description = "Public Elastic IP of the BIG-IP virtual server. Re-point the KEPT XC tenant's copilot-lab origin pool HERE (one XC-side change). DNS does NOT change — example.com hostnames resolve to XC's edge, not to this EIP."
  value       = aws_eip.bigip_vip.public_ip
}

output "bigip_vip_private_ip" {
  description = "External-interface secondary IP hosting the virtual server (the `--virtual-address`)."
  value       = var.bigip_vip_ip
}

output "bigip_mgmt_private_ip" {
  description = "BIG-IP management private IP — the remote host for the SSM port-forward."
  value       = aws_network_interface.bigip_mgmt.private_ip
}

output "xc_origin_target" {
  description = "What to point the KEPT XC tenant's origin pool at (the public VIP)."
  value       = "https://${aws_eip.bigip_vip.public_ip}"
}

output "ssm_tunnel_command" {
  description = "Open the BIG-IP management tunnel (then BIGIP_URL=https://127.0.0.1:18443)."
  value       = "aws --profile ${var.aws_profile} --region ${var.region} ssm start-session --target ${aws_instance.origin.id} --document-name AWS-StartPortForwardingSessionToRemoteHost --parameters 'host=${aws_network_interface.bigip_mgmt.private_ip},portNumber=443,localPortNumber=18443'"
}

output "bigip_lab_create_hint" {
  description = "Build the AS3 app tenant once onboarding is done and the tunnel is open."
  value       = "vpcopilot bigip-lab create --origin ${var.origin_private_ip}:${var.app_port} --virtual-address ${var.bigip_vip_ip}"
}
