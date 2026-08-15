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
  # `show sys mcp-state field-fmt` prints "    phase running" (space-separated),
  # so match that line directly rather than splitting on a colon that isn't there.
  local i
  for i in $(seq 1 90); do
    if tmsh show sys mcp-state field-fmt 2>/dev/null | grep -qiE 'phase:?[[:space:]]+running'; then
      echo "  mcp-state: running"; return 0
    fi
    echo "  waiting for mcpd running (try $i)"; sleep 10
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
# TRAP #2b: iControl LX INSTALL only accepts an RPM under /var/config/rest/downloads,
# NOT an arbitrary path like /var/tmp — installing from elsewhere FAILs in ~0.2s.
DL=/var/config/rest/downloads
mkdir -p "$DL"
if ! curl -fsSL -o "${DL}/${AS3_RPM}" "${AS3_URL}"; then
  echo "  pinned RPM name 404'd; resolving the real ${AS3_VERSION} asset from the GitHub API"
  AS3_URL=$(curl -fsSL "https://api.github.com/repos/F5Networks/f5-appsvcs-extension/releases/tags/v${AS3_VERSION}" \
    | grep -oE 'https://[^"]+f5-appsvcs-[^"]+\.noarch\.rpm' | head -1)
  AS3_RPM=$(basename "${AS3_URL}")
  echo "  resolved: ${AS3_URL}"
  curl -fsSL -o "${DL}/${AS3_RPM}" "${AS3_URL}"
fi
ls -l "${DL}/${AS3_RPM}"
task_id=$(curl -sk -u "admin:${ADMIN_PW}" -H "Content-Type: application/json" \
  -X POST https://localhost/mgmt/shared/iapp/package-management-tasks \
  -d "{\"operation\":\"INSTALL\",\"packageFilePath\":\"${DL}/${AS3_RPM}\"}" \
  | grep -oE '"id":"[^"]+"' | head -1 | cut -d'"' -f4)
echo "  install task id: ${task_id}"
# Poll the TASK status (so a FAILED surfaces instead of being masked by an empty /info).
for i in $(seq 1 30); do
  body=$(curl -sk -u "admin:${ADMIN_PW}" "https://localhost/mgmt/shared/iapp/package-management-tasks/${task_id}")
  status=$(echo "$body" | grep -oE '"status":"[^"]+"' | head -1 | cut -d'"' -f4)
  echo "  install status (try $i): ${status:-?}"
  [ "$status" = "FINISHED" ] && break
  [ "$status" = "FAILED" ] && { echo "  !! AS3 install FAILED: $body"; break; }
  sleep 5
done
# Confirm the endpoint registered (restnoded re-registers /shared/appsvcs after install).
for i in $(seq 1 12); do
  info=$(curl -sk -u "admin:${ADMIN_PW}" https://localhost/mgmt/shared/appsvcs/info 2>/dev/null)
  echo "$info" | grep -q '"version"' && { echo "  AS3 ready: ${info}"; break; }
  echo "  waiting for /shared/appsvcs (try $i)"; sleep 10
done

echo "== 4. base dataplane so AS3 has a VLAN/self-IP/route to build the app VIP on =="
tmsh create net vlan external interfaces add { ${EXTERNAL_IFACE} } 2>/dev/null || true
tmsh create net self vpcopilot_self address ${SELF_CIDR} vlan external allow-service default 2>/dev/null || true
tmsh create net route default_gw network default gw ${GATEWAY} 2>/dev/null || true
tmsh save sys config

echo "VPCOPILOT_BIGIP_ONBOARD_DONE — now open the tunnel and run: vpcopilot bigip-lab create ..."
