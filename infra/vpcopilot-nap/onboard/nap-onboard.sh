#!/usr/bin/env bash
# vpcopilot-nap onboarding — install F5 NGINX Plus + App Protect WAF (module) on
# Ubuntu 22.04 and stand up a reverse-proxy vhost to the Larkspur origin with App
# Protect enforcing.
#
# PROVEN end-to-end 2026-08-18: NGINX Plus R37 (1.29.8) + the App Protect module;
# a canned SQLi is blocked with the "Request Rejected / Your support ID is" page
# (HTTP 200 body — the same block page the copilot's validator already matches).
#
# Run OUT-OF-BAND over SSM by `make onboard` (never in user_data / TF state). The
# JWT (runtime license) + the repo client cert/key are delivered as $1/$2/$3.
set -uo pipefail

JWT_SRC="${1:?usage: nap-onboard.sh <license.jwt> <nginx-repo.crt> <nginx-repo.key>}"
CRT_SRC="${2:?need nginx-repo.crt — pkgs.nginx.com is mutual-TLS; the JWT is only the runtime license}"
KEY_SRC="${3:?need nginx-repo.key}"
ORIGIN="${ORIGIN:-10.30.10.22:8080}"      # Larkspur upstream (make onboard passes ORIGIN=)
POLICY_DIR=/etc/app_protect/conf
INCLUDE_DIR=/etc/nginx/conf.d
KEYRING=/usr/share/keyrings/nginx-archive-keyring.gpg
log(){ echo "== $*"; }
die(){ echo "!! $*" >&2; exit 1; }

# --- 0. runtime license -----------------------------------------------------
install -d -m 0755 /etc/nginx /etc/ssl/nginx
install -m 0640 "$JWT_SRC" /etc/nginx/license.jwt
log "runtime license -> /etc/nginx/license.jwt ($(wc -c </etc/nginx/license.jwt) bytes)"

# --- 1. prerequisites -------------------------------------------------------
export DEBIAN_FRONTEND=noninteractive
apt-get -qq update
apt-get -qq install -y apt-transport-https lsb-release ca-certificates wget gnupg2 curl

# --- 2. pkgs.nginx.com repo auth = subscription CLIENT CERT (mutual TLS) -----
# PROVEN on the box: pkgs.nginx.com returns "400 No required SSL certificate was
# sent" to any request without a client cert, so the JWT can NEVER authenticate the
# repo — it is only the runtime license (step 0). Use nginx-repo.crt + .key.
install -m 0644 "$CRT_SRC" /etc/ssl/nginx/nginx-repo.crt
install -m 0600 "$KEY_SRC" /etc/ssl/nginx/nginx-repo.key
# apt's acquire method drops privileges to the unprivileged _apt user, so the key
# must be readable by it — else "Could not load client certificate ... Error while
# reading file" and every fetch 400s. _apt group first, else world-read (lab).
chgrp _apt /etc/ssl/nginx/nginx-repo.key 2>/dev/null && chmod 0640 /etc/ssl/nginx/nginx-repo.key \
  || chmod 0644 /etc/ssl/nginx/nginx-repo.key
# A leftover JWT basic-auth cred (from an older attempt) makes apt take a path that
# skips the client cert -> 400. Remove it so the cert is always presented.
rm -f /etc/apt/auth.conf.d/nginx.conf

cat >/etc/apt/apt.conf.d/90pkgs-nginx <<'EOF'
Acquire::https::pkgs.nginx.com::Verify-Peer "true";
Acquire::https::pkgs.nginx.com::Verify-Host "true";
Acquire::https::pkgs.nginx.com::SslCert "/etc/ssl/nginx/nginx-repo.crt";
Acquire::https::pkgs.nginx.com::SslKey  "/etc/ssl/nginx/nginx-repo.key";
EOF

# TWO signing keys: nginx_signing.key covers plus + app-protect; the
# app-protect-security-updates repo (signatures/geoip) is signed by a SEPARATE key
# (…A5F6473795E778F4) published at its own URL.
: >"$KEYRING"
wget -qO - https://cs.nginx.com/static/keys/nginx_signing.key | gpg --dearmor >>"$KEYRING"
wget -qO - https://cs.nginx.com/static/keys/app-protect-security-updates.key | gpg --dearmor >>"$KEYRING"

# THREE repos: plus (nginx-plus), app-protect (module/engine/compiler),
# app-protect-security-updates (attack/bot signatures + threat-campaigns + geoip).
CODENAME="$(lsb_release -cs)"
for repo in plus app-protect app-protect-security-updates; do
  cat >/etc/apt/sources.list.d/nginx-${repo}.list <<EOF
deb [signed-by=$KEYRING] https://pkgs.nginx.com/${repo}/ubuntu ${CODENAME} nginx-plus
EOF
done

# --- 3. install App Protect -------------------------------------------------
# The `app-protect` metapackage pulls nginx-plus + nginx-plus-module-appprotect +
# engine + compiler + signatures + geoip. Do NOT co-list `nginx-plus` — the module
# pins a specific nginx-plus and listing both yields "held broken packages".
apt-get -qq update || die "apt update failed — check the cert/key + signing keys above"
apt-get -qq install -y app-protect || die "app-protect install failed"
MODULE=$(find /usr/lib/nginx/modules /etc/nginx/modules -name 'ngx_http_app_protect_module.so' 2>/dev/null | head -1)
[ -n "$MODULE" ] || die "app-protect module .so not found after install"
log "installed $(nginx -v 2>&1 | sed 's/nginx version: //') + App Protect module"

# --- 4. reverse-proxy vhost -> Larkspur, App Protect enforcing --------------
grep -q ngx_http_app_protect_module /etc/nginx/nginx.conf \
  || sed -i '1i load_module modules/ngx_http_app_protect_module.so;' /etc/nginx/nginx.conf
install -d -m 0755 "$POLICY_DIR" "$INCLUDE_DIR" /var/log/app_protect
# A minimal BLOCKING base policy for the Phase-0 spike (the base template blocks
# common attacks). The copilot later drops per-finding policies into a vpcopilot-
# managed include.
cat >"$POLICY_DIR/vpcopilot_default.json" <<'JSON'
{ "policy": { "name": "vpcopilot_default", "template": { "name": "POLICY_TEMPLATE_NGINX_BASE" },
  "applicationLanguage": "utf-8", "enforcementMode": "blocking" } }
JSON
LOGCFG=$(ls /etc/app_protect/conf/log_default.json /opt/app_protect/share/defaults/log_default.json 2>/dev/null | head -1)
{
  echo "# vpcopilot-managed"
  echo "upstream larkspur { server ${ORIGIN}; }"
  echo "server {"
  echo "    listen 80 default_server;"
  echo "    server_name vpcopilot.lab _;"
  echo "    app_protect_enable on;"
  echo "    app_protect_policy_file \"${POLICY_DIR}/vpcopilot_default.json\";"
  [ -n "$LOGCFG" ] && { echo "    app_protect_security_log_enable on;"; \
    echo "    app_protect_security_log \"$LOGCFG\" /var/log/app_protect/security.log;"; }
  echo "    location / { proxy_pass http://larkspur; proxy_set_header Host \$host; proxy_set_header X-Real-IP \$remote_addr; }"
  echo "}"
} >"$INCLUDE_DIR/vpcopilot-lab.conf"
rm -f /etc/nginx/conf.d/default.conf

# --- 5. validate + start (the App Protect enforcer is the nginx-app-protect svc) -
nginx -t || die "nginx -t failed — inspect the vhost / module load"
systemctl enable --now nginx-app-protect 2>/dev/null || true
systemctl enable nginx
systemctl restart nginx
sleep 5
[ "$(systemctl is-active nginx)" = active ] || die "nginx did not start"

# --- 6. smoke test ----------------------------------------------------------
legit=$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1/api/health)
atk=$(curl -s 'http://127.0.0.1/?id=1%27%20OR%20%271%27=%271')
echo "== smoke: legit /api/health -> HTTP $legit"
if echo "$atk" | grep -qiE 'request rejected|support id'; then
  echo "== smoke: attack sqli -> BLOCKED by NAP (support-id reject page) ✓"
else
  echo "== smoke: attack sqli -> NOT blocked — check policy/enforcer:"; echo "$atk" | head -4
fi
log "done. NGINX_POLICY_DIR=$POLICY_DIR NGINX_INCLUDE_DIR=$INCLUDE_DIR module=$MODULE"
