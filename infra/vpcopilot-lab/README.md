# infra/vpcopilot-lab — the copilot's Advanced-WAF BIG-IP lab (Terraform)

Stands up the copilot's own validation estate in **us-east-2**, all tagged
`Project=vpcopilot-lab`:

- **BIG-IP Advanced WAF VE** (`m5.xlarge`, F5 PAYG AWAF image) — two NICs, a public
  VIP Elastic IP, management reachable **only through an SSM port-forward** (never
  internet-published).
- **Larkspur Bank origin** (`t3.small`, Docker) behind the BIG-IP, on `10.30.10.22:8080`.
- Dedicated VPC `10.30.0.0/16`, deliberately separate from `nimbus-demo`.

It is adapted from `nimbus-demo/infra` with three deliberate changes: the **AWAF**
SKU (not GOOD — GOOD has no ASM and can't validate the WAF emitter), **Larkspur**
as the origin, and **no load generators**. The BIG-IP dataplane/WAF build is done
out-of-band by `onboard/bigip-onboard.sh` — nothing sensitive lands in state.

Credentials never live in this repo: the AWS profile is in `~/.aws/credentials`,
the SSH private key stays under `.secrets/` (gitignored), and Terraform state is
gitignored.

## 1. New-account prerequisites

```sh
# a named profile for the NEW account (credentials only ever land here)
aws configure --profile vpcopilot        # region us-east-2

# the AWAF Marketplace subscription must be accepted in the new account
#   Marketplace → "F5 BIG-IP Advanced WAF ... PAYG" → Subscribe (accept terms)
brew install --cask session-manager-plugin   # for the mgmt tunnel

make check        # profile + plugin + AWAF AMIs visible (NOT a subscription check)
```

**Subscription is the one prerequisite Terraform can't create — and image
*visibility* does not prove it.** Every account can see F5's public AWAF AMIs, so
`make check` reporting "N AWAF images visible" says nothing about entitlement. The
real test is a dry-run launch against a subnet, or `apply` itself: if it returns
`OptInRequired`, the error prints the exact product URL — accept terms there and
re-apply. Pin `bigip_ami` in `terraform.tfvars` to the subscribed image so the
retry can't drift to a different, unsubscribed SKU.

## 2. Apply

```sh
cp terraform.tfvars.example terraform.tfvars   # set aws_profile, xc_re_cidrs
make init
make plan                                       # generates .secrets/ keypair first
make apply
```

Key outputs: `bigip_vip_eip` (re-point the KEPT XC tenant's copilot-lab origin pool
here — **DNS is unchanged**; `example.com` hostnames resolve to XC's edge, not to
this EIP), `ssm_tunnel_command`, and `bigip_lab_create_hint`.

## 3. Onboard the BIG-IP (out-of-band)

The PAYG AMI self-licenses on boot, but ASM must be provisioned and AS3 installed —
`onboard/bigip-onboard.sh` does both and closes the two traps that cost real time
the first time (ASM provisioned before `mcpd` is up; AS3 absent from the image):

```sh
make tunnel                       # SSM forward to BIG-IP mgmt; leave it running
# in another shell, push+run the onboard script over the tunnel (see script header)
```

Then deploy the origin app and build the AS3 tenant:

```sh
make origin-deploy                # build+run Larkspur on the origin over SSM
export BIGIP_URL=https://127.0.0.1:18443
vpcopilot bigip-lab create --origin 10.30.10.22:8080 --virtual-address 10.30.10.190
```

## 4. Cost control — turn it off when idle

The AWAF appliance bills for EC2 **and** a PAYG software fee, but only while
`running`. Every target below is scoped to `Project=vpcopilot-lab`.

| command | effect | idle cost |
|---|---|---|
| `make lab-down` | **stop** both instances — kills EC2 + PAYG hourly, keeps the onboarded config on EBS (no re-onboarding) | EBS + ~2 EIPs (≈$7/mo) |
| `make lab-up` | start them again; fixed IPs and EIPs persist | — |
| `make lab-nuke` | `terraform destroy` — releases EIPs, deletes volumes | ~$0 (re-onboard next apply) |

Daily rhythm: `make lab-up` to work, `make lab-down` when done. `make lab-nuke`
for breaks of days or more. Set `bigip_mgmt_eip = false` to shave one EIP.

## Plugs into the migration runbook

This module is **P3** of the migration. It assumes the kept XC tenant
(`your-tenant` / `your-namespace`) — populate `xc_re_cidrs` from it and point its origin
pool at `bigip_vip_eip`. The origin's fixed IPs match the documented CLI examples
so `vpcopilot bigip-lab create` copy-pastes.
