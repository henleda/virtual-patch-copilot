#!/bin/bash
# vpcopilot-lab origin bootstrap. Installs Docker; the SSM agent already ships and
# runs on the Ubuntu 22.04 AWS image (via snap), so with the instance role the box
# is reachable through Session Manager with no inbound SSH rule. Larkspur itself is
# deployed post-boot by `make origin-deploy` (over SSM), not baked into user-data.
set -eux
export DEBIAN_FRONTEND=noninteractive

apt-get update
apt-get install -y docker.io
systemctl enable --now docker
usermod -aG docker ubuntu || true

echo "vpcopilot-lab origin ready $(date -u +%FT%TZ)" > /var/log/vpcopilot-origin.log
