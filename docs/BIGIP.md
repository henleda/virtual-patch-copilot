# Using virtual-patch-copilot with your own BIG-IP

This guide is for **BIG-IP administrators** — you know the GUI (virtual servers, WAF/ASM policies,
partitions) but you don't need to know AS3, iControl REST, or any DevOps tooling. The copilot does
that part.

**What it does:** it finds an exploitable vulnerability in your app, and — behind a human gate — puts
an **Advanced WAF band-aid in front of the app in minutes**, proves the exploit is actually blocked,
and takes the band-aid off again when your code fix ships.

**Why it's safe to try (read this first):**

- **It works in a private sandbox.** Every change lands inside one AS3 *tenant* (a partition). It
  **never** touches `/Common` or your other applications. Removing the tenant removes everything it
  did — cleanly.
- **Dry-run shows you first.** Every apply can preview the exact change before anything happens.
- **It rolls itself back.** If an applied band-aid doesn't actually block the exploit, the copilot
  removes it automatically. It never leaves a control that doesn't work.

---

## Three things to know

1. **A tenant is a private sandbox.** Think of it as a partition that only the copilot manages. It
   can't reach your production config, and deleting it is a clean undo.
2. **You never write AS3.** AS3 is just how the copilot talks to your BIG-IP under the hood — you
   point it at your app, it does the rest. If you've ever attached a WAF policy to a virtual server
   in the GUI, that's exactly what it's automating.
3. **Nothing is kept unless it's proven.** The copilot fires the finding's *real* exploit at the app
   after applying the band-aid; it only leaves the control on if the exploit is blocked **and** normal
   traffic still works.

---

## What your BIG-IP needs (pre-flight)

| Requirement | How to check (GUI) |
|---|---|
| **Advanced WAF (ASM) provisioned** | System ▸ Resource Provisioning ▸ **ASM = Nominal**. Without it there's no WAF to apply. |
| **AS3 installed** | The copilot's connection check (below) tells you. If it's missing, install the free **AS3** package once — it's an F5 add-on, not a config change ([download](https://github.com/F5Networks/f5-appsvcs-extension/releases)). |
| **A user the copilot can log in as** | `admin`, or a role with partition + AS3 rights. |
| **Reachability** | The management URL the copilot connects to. If your BIG-IP isn't reachable from where you run the copilot, forward the port (e.g. an SSH/SSM tunnel) and point `BIGIP_URL` at your end of it. |
| **Version** | BIG-IP 16.1+ with a recent AS3. |

---

## Step 1 — connect to your BIG-IP

Give the copilot three things. Easiest is the **console**: run `vpcopilot console`, open **⚙ Setup →
Advanced integrations → BIG-IP**, fill them in, and **Save**. (Or put them in your `.env`.)

```
BIGIP_URL        # e.g. https://bigip.internal:443  (or your tunnel's near end)
BIGIP_USER       # e.g. admin
BIGIP_PASSWORD
```

**Test the connection** — this tells you, in plain terms, whether the box answers, whether AS3 is
installed, and whether the login worked:

```bash
vpcopilot bigip-lab status
```

The Setup page shows the same thing. A self-signed certificate warning is expected for a
self-managed box — the copilot doesn't require a trusted certificate.

## Step 2 — stand up a sandbox in front of your app

This creates the private tenant (partition) that fronts your app — a plain HTTP virtual server
pointing at your app's origin, **with no WAF yet**. It's idempotent: run it again and nothing
changes.

```bash
vpcopilot bigip-lab create \
  --tenant my_app \                       # the sandbox name (letters/digits/_/-)
  --origin 10.0.0.20:8080 \               # where your app actually runs (host:port)
  --virtual-address 10.0.0.190            # the IP the sandbox listens on
```

`vpcopilot bigip-lab rm --tenant my_app` removes it entirely when you're done.

## Step 3 — scan your app

Point the copilot at your app's code (read-only, no changes) so it has findings to mitigate. See
**[TRY_IT.md](TRY_IT.md)** — start on a known-vulnerable app (VAmPI / crAPI) if you want to see it
work first.

## Step 4 — apply a band-aid, and watch it prove itself

Preview first (**nothing changes** — AS3 reports what it *would* do):

```bash
vpcopilot apply-bigip --finding <finding-id> --tenant my_app --url https://my-app.internal --dry-run
```

Then apply it for real. By default this is a **safe smoke test**: it attaches the band-aid, fires the
exploit, shows you `before 200 → after 403 blocked`, and then **removes it again**. Add `--keep` to
leave it enforcing.

```bash
vpcopilot apply-bigip --finding <finding-id> --tenant my_app --url https://my-app.internal --keep
```

If the band-aid doesn't block the exploit, the copilot rolls the sandbox back to clean-slate and
tells you — it won't leave a control that isn't working.

## Step 5 — retire it when your code fix ships

The band-aid is temporary. When the real fix is deployed, take it off (the app stays up — only the
WAF comes off):

```bash
vpcopilot retire-bigip --finding <finding-id> --tenant my_app
```

---

## What's guarded (so you can hand this to anyone)

- **The sandbox tenant is a hard boundary** — a change or a delete can only ever affect
  `/<your-tenant>/`. `/Common` is refused unconditionally, and any tenant listed in
  `VPCOPILOT_PROTECTED_BIGIP_TENANTS` needs an explicit `--allow-protected-tenant`.
- **Dry-run** previews every change; **auto-rollback** removes any band-aid that doesn't block.
- **Every change is on the record** — what changed, which vulnerability justified it, whether it's
  still live, and who ran it — exportable as an evidence bundle for a change board (see
  **[AUDIT.md](AUDIT.md)**).

## Troubleshooting

| You see | What it means / fix |
|---|---|
| `unreachable` | The URL is wrong, or the box isn't reachable from here — check `BIGIP_URL`, or set up a tunnel and point at its near end. |
| `AS3 unavailable` / `AS3 not installed` | The appliance is up but the AS3 package isn't installed. Install it once (it's an F5 add-on). |
| `authentication failed` | Wrong `BIGIP_USER`/`BIGIP_PASSWORD`, or the user lacks partition/AS3 rights. |
| `no Advanced-WAF band-aid` | This finding's best control (e.g. rate-limit, bot) has no Advanced-WAF form — mitigate it on F5 Distributed Cloud, or ship the code fix. |
| `tenant ... not found` | Run `vpcopilot bigip-lab create` first — the apply attaches to a sandbox that already exists. |
| certificate warning | Expected for a self-managed/lab box; the copilot doesn't require a trusted cert. |

## What BIG-IP can patch today

The copilot applies the **value-constraint** Advanced-WAF band-aid (the `service_policy` form) today.
Signature-set (`waf`), response-masking (`waf_data_guard`), and OpenAPI (`api_schema`) forms are on
the roadmap. Rate-limiting, malicious-user, and bot defense are **F5 Distributed Cloud** features (or
a code fix) — the copilot will say so rather than emit a control that enforces nothing.

> **Coming next:** a **BIG-IP** option directly in the console's ④ Mitigate step, so the whole flow —
> apply, watch it validate, keep or retire — is a few clicks in the GUI, no CLI required. Today the
> console handles the connection (Setup) and the apply itself is the short command above.
