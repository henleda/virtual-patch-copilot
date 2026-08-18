#!/usr/bin/env bash
# Minimal bootstrap. NAP itself is installed OUT-OF-BAND (onboard/nap-onboard.sh,
# shipped over SSM) so the JWT license never lands in user_data or Terraform state.
set -euxo pipefail

# Ensure the SSM agent is running (Canonical's 22.04 AMI ships it as a snap).
snap install amazon-ssm-agent --classic || true
systemctl enable --now snap.amazon-ssm-agent.amazon-ssm-agent.service 2>/dev/null \
  || systemctl enable --now amazon-ssm-agent 2>/dev/null || true

# A stable hostname for logs.
hostnamectl set-hostname vpcopilot-nap || true
