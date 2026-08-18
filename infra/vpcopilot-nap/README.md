# vpcopilot-nap — the F5 WAF for NGINX (App Protect v4) proof box

A single **NGINX Plus + App Protect v4** EC2 that fronts the **existing Larkspur origin** in the
`vpcopilot-lab` VPC, so a finding's declarative band-aid can be applied and validated on a **real
NAP box** — the L2 analogue of the BIG-IP lab. Design: [`docs/design/nginx-app-protect-apply.md`](../../docs/design/nginx-app-protect-apply.md).

**Why it reuses the lab VPC:** the NGINX box must sit in the same VPC to reach Larkspur
(`10.30.10.22:8080`), and the lab's origin SG already admits `:8080` from the whole VPC CIDR — so this
module data-sources the lab VPC/subnet by tag and adds **one** box, with **no change to
`vpcopilot-lab`**.

## Prerequisites

1. **AWS SSO** logged in: `aws sso login --profile vpcopilot` (account `113938649684`, us-east-2).
2. **The `vpcopilot-lab` estate exists** (this box reuses its VPC + origin). `make check` verifies it.
3. **The Larkspur origin is running.** For a proof, start just the origin in `../vpcopilot-lab`
   (`make -C ../vpcopilot-lab lab-up`, then optionally `make -C ../vpcopilot-lab nap-down`… — or start
   the single origin instance). The BIG-IP can stay stopped.
4. **Three NGINX subscription files from MyF5** on your laptop:
   - `license.jwt` — the R33+ **runtime** license (placed at `/etc/nginx/license.jwt`).
   - `nginx-repo.crt` + `nginx-repo.key` — the **repo** client cert+key. `pkgs.nginx.com` does
     mutual-TLS (it returns *"400 No required SSL certificate was sent"* to the JWT), so the cert+key
     — not the JWT — are what install the packages.
5. `terraform`, the AWS CLI, and the SSM `session-manager-plugin`.

## Stand it up

```bash
make check                 # profile + lab-VPC readiness
make apply                 # generates the keypair, then terraform apply (you approve the plan)
make onboard JWT=~/Downloads/nginx-one-A-S00033488.jwt \
             CERT=~/Downloads/nginx-repo.crt KEY=~/Downloads/nginx-repo.key
```

`apply` creates: the box (Ubuntu 22.04, `t3.medium`) in the lab external subnet at `10.30.10.30`, a
public EIP, an SG (vhost `:80`; SSH via SSM), an SSM instance role, and a keypair from `.secrets/`.
**`terraform apply` is yours to run** — provisioning is user-gated.

`onboard` ships `onboard/nap-onboard.sh` + the JWT to the box **over SSM** (never in `user_data` or
state), installs NGINX Plus + App Protect v4, and stands up a reverse-proxy vhost to Larkspur with
App Protect enforcing a blocking base policy. It ends with a smoke test (benign → 200, canned SQLi →
NAP block). **This is the NAP Phase-0 live spike** — the onboarding script carries `# VERIFY:` markers
where F5's JWT-era install specifics may need a tweak on the box (the repo-auth line, package names,
the bundled log path), the same way the BIG-IP onboarding was iterated on first contact.

## Reach it

```bash
make tunnel                # SSM port-forward: 127.0.0.1:2223 -> box:22 (leave running)
# in another shell — the copilot's NGINX transport env:
export NGINX_SSH_HOST=127.0.0.1 NGINX_SSH_PORT=2223 NGINX_SSH_USER=ubuntu \
       NGINX_SSH_KEY=$PWD/.secrets/vpcopilot_nap.pem \
       NGINX_RELOAD_CMD='sudo nginx -s reload' \
       NGINX_POLICY_DIR=/etc/app_protect/conf NGINX_INCLUDE_DIR=/etc/nginx/conf.d \
       NGINX_NAP_VERSION=v4
make ssh                   # or an interactive shell over the same tunnel
make shell                 # or a plain SSM shell (no key)
```

Fire exploit/legit **through** the box at `http://<nap_public_ip>/…` (see `terraform output http_url`).

## Cost control

```bash
make nap-down              # STOP the box (kills the hourly EC2 charge; keeps the install)
make nap-up                # START it again
make nap-nuke              # terraform destroy (re-onboard on the next apply)
```

## Secrets

`.secrets/` (keypair), `*.jwt`, `terraform.tfvars`, and all state are `.gitignore`d. The JWT is
delivered to the box out-of-band and lives only at `/etc/nginx/license.jwt` there — never in the repo
or Terraform state. (SSM command parameters are recorded in CloudTrail; acceptable for a lab — rotate
the token from MyF5 if that matters.)
