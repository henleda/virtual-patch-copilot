# Using virtual-patch-copilot with your own NGINX (App Protect)

This guide is for **NGINX administrators** running **F5 WAF for NGINX (NGINX App Protect)** — you know
`nginx.conf`, `server`/`location` blocks, and a `nginx -s reload`, but you don't need to hand-write an
App Protect policy or any DevOps tooling. The copilot does that part.

**What it does:** it finds an exploitable vulnerability in your app, and — behind a human gate — puts
an **App Protect band-aid in front of the app in minutes**, proves the exploit is actually blocked,
and takes the band-aid off again when your code fix ships. It is the NGINX twin of the BIG-IP flow in
**[BIGIP.md](BIGIP.md)** — the *same finding, same band-aid*, emitted for the WAF you already run.

**Why it's safe to try (read this first):**

- **It only touches its own vhost.** Every file the copilot writes is named `vpcopilot-…` and lives in
  its own managed include directory. It **never** edits your existing `server` blocks or policies —
  removing its vhost is a clean undo.
- **`nginx -t` gates every change.** Nothing is reloaded unless the box's own config test passes.
- **It rolls itself back.** If an applied band-aid doesn't actually block the exploit, the copilot
  removes it automatically and reloads. It never leaves a control that doesn't work.

---

## Three things to know

1. **The copilot owns one `server` (a private sandbox).** It manages a single named vhost that
   reverse-proxies to your app, and drops each band-aid into a `vpcopilot-active/` include on that
   `location`. It can't reach your other vhosts, and removing its vhost is a clean undo.
2. **You never write an App Protect policy.** SSH is just how the copilot ships the policy file and
   reloads — you point it at your app's origin, it does the rest. If you've ever set
   `app_protect_policy_file` on a `location`, that's exactly what it's automating.
3. **Nothing is kept unless it's proven.** The copilot fires the finding's *real* exploit at the app
   **through the box** after applying the band-aid; it only leaves the control on if the exploit is
   blocked **and** normal traffic still works. (App Protect loads a policy into its enforcer a second
   or two after a reload, so the copilot waits for enforcement to go live before it decides.)

---

## What your NGINX box needs (pre-flight)

| Requirement | How to check |
|---|---|
| **NGINX Plus + App Protect installed** | `nginx -V 2>&1 \| grep app-protect`, or the copilot's `nginx-lab status` reports whether the module is loaded. The copilot **attaches** policies — it does not install App Protect. |
| **SSH access with reload rights** | A user who can write the policy/include dirs **and** run `nginx -t` + the reload (root, or `sudo NOPASSWD` scoped to `nginx -s reload`). A copy-only user can't apply. |
| **Reachability** | Where the copilot runs must reach the box over SSH. If it's not directly reachable, forward the port (an SSH/SSM tunnel) and point `NGINX_SSH_HOST` at your end of it. |
| **The validation URL goes *through* the box** | The app URL you validate against must resolve to the NGINX vhost — not a CDN in front, not the origin behind — or the exploit probe proves nothing. |
| **Version** | NGINX Plus with App Protect (the v4-style module: `ngx_http_app_protect_module.so` + raw-JSON `app_protect_policy_file`). |

---

## Step 1 — connect to your NGINX box

Give the copilot how to reach the box over SSH — in the **console** (`vpcopilot console`, **⚙ Setup**)
or your `.env`:

```
NGINX_SSH_HOST         # e.g. nginx.internal  (or your tunnel's near end, 127.0.0.1)
NGINX_SSH_PORT         # default 22
NGINX_SSH_USER         # a user with write + reload rights
NGINX_SSH_KEY          # path to the private key (preferred)  — or NGINX_SSH_PASSWORD
NGINX_RELOAD_CMD       # default: sudo nginx -s reload
NGINX_POLICY_DIR       # default: /etc/app_protect/conf
NGINX_INCLUDE_DIR      # default: /etc/nginx/conf.d
```

**Test the connection** — this tells you whether the box answers over SSH and whether the App Protect
module is loaded:

```bash
vpcopilot nginx-lab status
```

## Step 2 — stand up the copilot's vhost in front of your app

This creates the private vhost that fronts your app — a reverse proxy to your app's origin, whose
`location` includes the copilot's (empty) managed policy dir, **with no band-aid yet**. Idempotent:
run it again and it converges.

```bash
vpcopilot nginx-lab create \
  --server vpcopilot.lab \                 # the server_name the copilot owns
  --origin 10.0.0.20:8080                  # where your app actually runs (host:port)
```

`vpcopilot nginx-lab rm --server vpcopilot.lab` removes it when you're done. The nginx catch-all `_`
server is refused outright, and any server in `VPCOPILOT_PROTECTED_NGINX_SITES` needs
`--allow-protected-site`.

## Step 3 — scan your app

Point the copilot at your app's code (read-only, no changes) so it has findings to mitigate. See
**[TRY_IT.md](TRY_IT.md)** — start on a known-vulnerable app (VAmPI / crAPI) if you want to see it
work first.

## Step 4 — apply a band-aid, and watch it prove itself

Preview first (**nothing changes** — the copilot stages the policy and runs `nginx -t`, then rolls
the staging back):

```bash
vpcopilot apply-nginx --finding <finding-id> --url http://my-app.internal --dry-run
```

Then apply it for real. By default this is a **safe smoke test**: it writes the policy + managed
include, reloads, fires the exploit **through the box**, shows you `before → after blocked`, and then
**removes it again**. Add `--keep` to leave it enforcing.

```bash
vpcopilot apply-nginx --finding <finding-id> --url http://my-app.internal --keep
```

If the band-aid doesn't block the exploit, the copilot removes it and reloads — it won't leave a
control that isn't working.

## Step 5 — retire it when your code fix ships

The band-aid is temporary. When the real fix is deployed, take it off (the app stays up — only the
managed include comes off):

```bash
vpcopilot retire-nginx --finding <finding-id> --server vpcopilot.lab
```

---

## What's guarded (so you can hand this to anyone)

- **The copilot only ever writes `vpcopilot-` files** in its own include dir — a change or a detach
  can never touch your own `server` blocks or an `app_protect_policy_file` you set. The nginx
  catch-all `_` server is refused unconditionally; any server in `VPCOPILOT_PROTECTED_NGINX_SITES`
  needs an explicit `--allow-protected-site`.
- **`nginx -t` gates every change**; **auto-rollback** removes any band-aid that doesn't block.
- **Every change is on the record** — what changed, which vulnerability justified it, whether it's
  still live, and who ran it — exportable as an evidence bundle (see **[AUDIT.md](AUDIT.md)**).

## Troubleshooting

| You see | What it means / fix |
|---|---|
| `unreachable` | The box isn't reachable over SSH from here — check `NGINX_SSH_HOST/PORT/KEY`, or open a tunnel and point at its near end. |
| `App Protect: NOT loaded` | The box answers but the App Protect module isn't loaded — `load_module modules/ngx_http_app_protect_module.so;` and confirm the enforcer service is running. |
| `nginx -t failed` | The box rejected the config — the copilot never reloads a config that fails the test, and shows you the box's own error. |
| `no App Protect band-aid` | This finding's best control (e.g. rate-limit, bot) has no App Protect form — mitigate it on F5 Distributed Cloud, or ship the code fix. |
| `did not block — rolled back` | The band-aid attached and reloaded but the exploit still got through (even after waiting for enforcement) — the copilot removed it rather than leave a control that doesn't work. |

## What NGINX App Protect can patch today

The **same three forms as BIG-IP**, each proven on a live NGINX Plus + App Protect box (R37):

| Form | Control | What it does |
|---|---|---|
| **value-constraint** | `service_policy` | rejects a request whose parameter is out of range (e.g. a negative transfer amount) |
| **response-masking** | `waf_data_guard` | masks leaked secrets (PAN / SSN) in the response |
| **API-contract** | `api_schema` | blocks a served-but-undocumented (off-contract) endpoint |

**Signature sets (`waf`) are honestly declined** — NAP keeps freshly-imported signatures in staging
(log-only), so a signature band-aid would look applied and block nothing. Rate-limiting,
malicious-user, and bot defense have no App Protect object and are F5 Distributed Cloud features (or a
code fix).

**In the console:** expand **Apply on your own NGINX (App Protect)** in the ④ Mitigate step — pick a
finding, apply, watch it validate, keep or retire. The commands above are the headless equivalent.

![Apply on your own BIG-IP / NGINX, live in the console](images/apply-your-own-waf.png)
