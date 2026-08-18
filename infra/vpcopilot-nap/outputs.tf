output "nap_instance_id" {
  description = "NGINX+NAP EC2 id — the SSM tunnel / onboarding target."
  value       = aws_instance.nap.id
}

output "nap_public_ip" {
  description = "Public Elastic IP of the box. Fire exploit/legit at http://<this>/ (goes THROUGH NAP to Larkspur)."
  value       = aws_eip.nap.public_ip
}

output "nap_private_ip" {
  description = "Private IP of the box in the lab VPC."
  value       = aws_instance.nap.private_ip
}

output "http_url" {
  description = "The URL that resolves THROUGH the NAP vhost — the copilot's --url for apply/validate."
  value       = "http://${aws_eip.nap.public_ip}"
}

output "ssh_tunnel_command" {
  description = "Open an SSM port-forward to the box's SSH (then NGINX_SSH_HOST=127.0.0.1 NGINX_SSH_PORT=2223)."
  value       = "aws --profile ${var.aws_profile} --region ${var.region} ssm start-session --target ${aws_instance.nap.id} --document-name AWS-StartPortForwardingSession --parameters 'portNumber=22,localPortNumber=2223'"
}

output "origin_target" {
  description = "The Larkspur origin the NGINX vhost proxies to. It must be RUNNING — start it in the vpcopilot-lab estate (make -C ../vpcopilot-lab lab-up, or start just the origin instance)."
  value       = "${var.origin_private_ip}:${var.app_port}"
}

output "onboard_hint" {
  description = "Install NAP out-of-band once the box is up (delivers the JWT over SSM; nothing lands in state)."
  value       = "make onboard JWT=~/Downloads/nginx-one-*.jwt"
}
