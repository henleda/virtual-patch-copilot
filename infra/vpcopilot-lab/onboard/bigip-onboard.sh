#!/bin/bash
# vpcopilot-lab BIG-IP Advanced-WAF onboarding — run ON the BIG-IP after apply,
# over the SSM tunnel. This is the AWAF superset of the nimbus LTM onboard: it
# closes the two documented traps (ASM provisioned before mcpd is up; AS3 absent
# from the PAYG image), then lays the base dataplane so the copilot's AS3 tenant
# (`vpcopilot bigip-lab create`) has a VLAN/self-IP/route to attach the VIP to.
#
# Transfer + run from your laptop through the tunnel (avoids tmsh nested-quoting):
#   ssh -i .secrets/vpcopilot_lab.pem admin@127.0.0.1 -p 22 'run util bash -c "cat > /var/tmp/onboard.sh"' < onboard/bigip-onboard.sh
#   ssh -i .secrets/vpcopilot_lab.pem admin@127.0.0.1 'run util bash -c "bash /var/tmp/onboard.sh"'
# (127.0.0.1:22 is the near end of an SSM forward to the BIG-IP mgmt :22, or use
#  `make tunnel` for the :443 iControl path and drive AS3 over REST instead.)
set -x

# Match the Terraform defaults; override via env if you changed the variables.
EXTERNAL_IFACE="${EXTERNAL_IFACE:-1.1}"
SELF_CIDR="${SELF_CIDR:-10.30.10.10/24}"
GATEWAY="${GATEWAY:-10.30.10.1}"
ADMIN_PW="${BIGIP_ADMIN_PASSWORD:-admin}"
AS3_VERSION="${AS3_VERSION:-3.56.0}"
# NOTE: verify the exact asset name on the release page — the build suffix moves.
#   https://github.com/F5Networks/f5-appsvcs-extension/releases
AS3_RPM="${AS3_RPM:-f5-appsvcs-${AS3_VERSION}-4.noarch.rpm}"
AS3_URL="https://github.com/F5Networks/f5-appsvcs-extension/releases/download/v${AS3_VERSION}/${AS3_RPM}"

wait_mcpd() {
  # TRAP #1: user-data runs before mcpd is up (~89s); a tmsh/provision call then
  # fails silently and leaves WAF unprovisioned while EC2 reports status-ok.
  local i state
  for i in $(seq 1 90); do
    state=$(tmsh show sys mcp-state field-fmt 2>/dev/null | awk -F: '/phase/{gsub(/ /,"",$2); print $2; exit}')
    echo "  mcp-state phase=${state:-unknown} (try $i)"
    [ "$state" = "running" ] && return 0
    sleep 10
  done
  echo "!! mcpd did not reach 'running' — aborting before it fails silently"; return 1
}

echo "== 1. wait for mcpd =="
wait_mcpd || exit 1

echo "== 2. provision ASM (Advanced WAF) nominal — restarts daemons, budget ~10-15 min =="
tmsh modify sys provision asm level nominal
sleep 30
wait_mcpd || exit 1
tmsh show sys provision | grep -i -E 'asm|ltm'

echo "== 3. install AS3 ${AS3_VERSION} (TRAP #2: absent from the PAYG image; scp is broken on the tmsh shell, so the box fetches it itself) =="
curl -fsSL -o "/var/tmp/${AS3_RPM}" "${AS3_URL}"
task=$(curl -sk -u "admin:${ADMIN_PW}" -H "Content-Type: application/json" \
  -X POST https://localhost/mgmt/shared/iapp/package-management-tasks \
  -d "{\"operation\":\"INSTALL\",\"packageFilePath\":\"/var/tmp/${AS3_RPM}\"}")
echo "  install task: ${task}"
for i in $(seq 1 30); do
  info=$(curl -sk -u "admin:${ADMIN_PW}" https://localhost/mgmt/shared/appsvcs/info 2>/dev/null)
  echo "  as3 info (try $i): ${info}"
  echo "${info}" | grep -q '"version"' && break
  sleep 10
done

echo "== 4. base dataplane so AS3 has a VLAN/self-IP/route to build the app VIP on =="
tmsh create net vlan external interfaces add { ${EXTERNAL_IFACE} } 2>/dev/null || true
tmsh create net self vpcopilot_self address ${SELF_CIDR} vlan external allow-service default 2>/dev/null || true
tmsh create net route default_gw network default gw ${GATEWAY} 2>/dev/null || true
tmsh save sys config

echo "VPCOPILOT_BIGIP_ONBOARD_DONE — now open the tunnel and run: vpcopilot bigip-lab create ..."
