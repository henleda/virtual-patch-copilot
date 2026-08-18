#!/usr/bin/env bash
# vpcopilot-nap onboarding — install NGINX Plus + App Protect WAF v4 on Ubuntu 22.04
# and stand up a reverse-proxy vhost to the Larkspur origin with App Protect enforcing.
#
# Run OUT-OF-BAND over SSM by `make onboard` (never in user_data / Terraform state).
# The JWT license is delivered as $1 and copied to /etc/nginx/license.jwt.
#
# HONESTY: F5 moved NGINX Plus to JWT licensing in R33 and gated the v4 install docs
# behind MyF5, so the repo-auth block below is the best-known JWT method and is marked
# `# VERIFY:` where it may need adjustment against the current doc:
#   https://docs.nginx.com/nginx-app-protect-waf/v4/admin-guide/install/
# This is the NAP Phase-0 live spike — expect to iterate it on the box the first time,
# exactly as the BIG-IP onboarding was iterated (the mcp-state / AS3-path fixes).
set -uo pipefail

JWT_SRC="${1:?usage: nap-onboard.sh <path-to-license.jwt>}"
ORIGIN="${ORIGIN:-10.30.10.22:8080}"      # Larkspur upstream (make onboard passes ORIGIN=)
POLICY_DIR=/etc/app_protect/conf
INCLUDE_DIR=/etc/nginx/conf.d
log(){ echo "== $*"; }
die(){ echo "!! $*" >&2; exit 1; }

# --- 0. license -------------------------------------------------------------
install -d -m 0755 /etc/nginx
install -m 0640 "$JWT_SRC" /etc/nginx/license.jwt
log "license placed at /etc/nginx/license.jwt ($(wc -c </etc/nginx/license.jwt) bytes)"

# --- 1. prerequisites -------------------------------------------------------
export DEBIAN_FRONTEND=noninteractive
apt-get -qq update
apt-get -qq install -y apt-transport-https lsb-release ca-certificates wget gnupg2 curl

# --- 2. pkgs.nginx.com repo auth via the JWT --------------------------------
# VERIFY: R33+ uses the JWT as the apt credential to pkgs.nginx.com — apt sends the
# JWT string as the password for `machine pkgs.nginx.com`. If your subscription
# still uses the certificate method, drop nginx-repo.crt / nginx-repo.key into
# /etc/ssl/nginx/ and use the cert `Acquire` lines from the install doc instead.
JWT="$(tr -d '\n' </etc/nginx/license.jwt)"
install -d -m 0755 /etc/apt/auth.conf.d
umask 077
cat >/etc/apt/auth.conf.d/nginx.conf <<EOF
machine pkgs.nginx.com login token password ${JWT}
EOF
umask 022

wget -qO - https://cs.nginx.com/static/keys/nginx_signing.key | gpg --dearmor \
  | tee /usr/share/keyrings/nginx-archive-keyring.gpg >/dev/null

CODENAME="$(lsb_release -cs)"
cat >/etc/apt/sources.list.d/nginx-plus.list <<EOF
deb [signed-by=/usr/share/keyrings/nginx-archive-keyring.gpg] https://pkgs.nginx.com/plus/ubuntu ${CODENAME} nginx-plus
EOF
# VERIFY: the app-protect repo path for your NAP v4 release.
cat >/etc/apt/sources.list.d/nginx-app-protect.list <<EOF
deb [signed-by=/usr/share/keyrings/nginx-archive-keyring.gpg] https://pkgs.nginx.com/app-protect/ubuntu ${CODENAME} nginx-plus
EOF
cat >/etc/apt/preferences.d/90nginx <<'EOF'
Package: *
Pin: origin pkgs.nginx.com
Pin-Priority: 900
EOF

# --- 3. install nginx-plus + app-protect ------------------------------------
apt-get -qq update || die "apt update failed — most likely repo auth (see VERIFY in step 2)"
apt-get -qq install -y nginx-plus            || die "nginx-plus install failed (repo auth / subscription)"
apt-get -qq install -y app-protect           || die "app-protect (v4 module + bd) install failed"
apt-get -qq install -y app-protect-attack-signatures || log "signatures pkg not installed (VERIFY name)"
# VERIFY: the three package names are the documented NAP v4 set; adjust if the repo
# lists them differently (e.g. a version-suffixed signatures package).

# load the App Protect module in the main conf if not already present
if ! grep -q 'ngx_http_app_protect_module.so' /etc/nginx/nginx.conf; then
  sed -i '1i load_module modules/ngx_http_app_protect_module.so;' /etc/nginx/nginx.conf
fi

# --- 4. reverse-proxy vhost -> Larkspur, App Protect enforcing --------------
install -d -m 0755 "$POLICY_DIR" "$INCLUDE_DIR" /var/log/app_protect
# NAP's base template blocks common attacks in BLOCKING mode. Use a minimal
# blocking policy for the Phase-0 spike so we can prove NAP actually blocks before
# the copilot emits per-finding policies into a vpcopilot- managed include.
DEFAULT_POLICY="$POLICY_DIR/vpcopilot_default.json"
cat >"$DEFAULT_POLICY" <<'JSON'
{ "policy": { "name": "vpcopilot_default", "template": { "name": "POLICY_TEMPLATE_NGINX_BASE" },
  "applicationLanguage": "utf-8", "enforcementMode": "blocking" } }
JSON

cat >"$INCLUDE_DIR/vpcopilot-lab.conf" <<EOF
# vpcopilot-managed
upstream larkspur { server ${ORIGIN}; }

server {
    listen 80 default_server;
    server_name vpcopilot.lab _;

    app_protect_enable on;
    app_protect_policy_file "${DEFAULT_POLICY}";
    # VERIFY: bundled security-log format path — adjust to the one your app-protect
    # package ships (commonly /etc/app_protect/conf/log_default.json).
    app_protect_security_log_enable on;
    app_protect_security_log "/etc/app_protect/conf/log_default.json" /var/log/app_protect/security.log;

    location / {
        proxy_pass http://larkspur;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
    }
}
EOF
rm -f /etc/nginx/conf.d/default.conf 2>/dev/null || true

# --- 5. validate + start ----------------------------------------------------
nginx -t || die "nginx -t failed — inspect the vhost / module load above"
systemctl enable nginx
systemctl restart nginx          # first bring-up: restart so the module + bd load
sleep 3

# --- 6. smoke test ----------------------------------------------------------
log "smoke: benign request (expect 200 from Larkspur)"
curl -s -o /dev/null -w '  legit  -> HTTP %{http_code}\n' 'http://127.0.0.1/api/health' || true
log "smoke: canned SQLi (expect a NAP block, NOT a 200 from Larkspur)"
curl -s -o /dev/null -w "  attack -> HTTP %{http_code}\n" "http://127.0.0.1/?id=1%27%20OR%20%271%27=%271" || true
log "A NAP block returns a support-id reject page (not Larkspur's 200). Check the violation in"
log "/var/log/app_protect/security.log. If enforcement looks off, resolve the design's §10 items."
log "done. NGINX_POLICY_DIR=$POLICY_DIR  NGINX_INCLUDE_DIR=$INCLUDE_DIR"
