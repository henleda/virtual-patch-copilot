# Try it — on safe, known-vulnerable apps first

The best way to learn virtual-patch-copilot is to point it at a deliberately-vulnerable open-source
app before you run it on your own code. Two great targets, both maintained as security-training labs:

| App | What it is | Good for |
|---|---|---|
| [**VAmPI**](https://github.com/erev0s/VAmPI) | one small Flask API with intentional OWASP-API flaws | fastest first run (single service) |
| [**OWASP crAPI**](https://github.com/OWASP/crAPI) | a multi-service "completely ridiculous API" lab | a richer, realistic spread of findings |

There are two ways to run:

- **Path A — Scan (read-only).** Needs only a model API key. Makes **no** changes to anything —
  no cloud, no GitHub, no writes to the target. This is the safe on-ramp; do this first.
- **Path B — Full loop behind F5 XC.** Actually mitigate live, open code-fix PRs, and retire.
  Needs an F5 Distributed Cloud tenant and a domain you control. Advanced; do it once Path A makes
  sense to you.

---

## Path A — Scan a safe repo (2 minutes, zero risk)

### 1. Install + a model key

```bash
pip install -e ".[console]"
cp .env.example .env        # then add ONE model key, e.g. ANTHROPIC_API_KEY
```

That single key is all Path A needs. The copilot is model-independent — to run on OpenAI / Gemini /
a local Ollama model instead, set that provider's key and edit `config/agents.yaml` (see
[MODELS.md](../MODELS.md)). No XC or GitHub credentials are required to scan.

### 2. Get a target

```bash
git clone https://github.com/erev0s/VAmPI ../VAmPI          # small — start here
# or, for more findings:
git clone https://github.com/OWASP/crAPI ../crapi
```

### 3. Scan it

Either from the console (recommended — it walks you through the flow):

```bash
vpcopilot console        # http://127.0.0.1:8787
```
Open **① Scan**, put the repo path (e.g. `../VAmPI`) in *Target repo*, and **Run scan**. It
auto-advances to **② Review** when done.

Or headless:

```bash
vpcopilot scan ../VAmPI --out out-vampi
vpcopilot report --open           # opens a shareable HTML dashboard of the results
```

`scan` performs **no** live writes — it only reads the repo and writes results to `out-vampi/`
(findings, triage, generated XC policies, code-fix PR drafts, and `report.html`). Safe to run
anywhere.

### 4. Read the results

In the console's **② Review** step (or `report.html`), for each verified finding you'll see the
severity, the effective endpoint, the **recommended XC control**, and — click a row — the exploit,
the offending code, and the generated band-aid. Roughly what to expect:

- **VAmPI** → SQL injection on the login/register endpoints, broken object-level auth (BOLA) on the
  user routes, and weak/again-guessable auth — routed to `service_policy` / `waf` / `api_schema`.
- **crAPI** → BOLA (vehicle/mechanic), mass assignment, JWT problems, unauthenticated data exposure,
  and OTP brute-force — a spread across `service_policy`, `api_schema`, `rate_limit`, `waf_data_guard`.

Every finding also gets a drafted **code fix** (the cure) — band-aids are temporary by design.

That's the whole safe experience. You've seen what it finds and what it would do, with nothing
changed anywhere.

> Prefer to look before you even scan? A fully-worked, offline sample lives in `demo/out` — run
> `VPCOPILOT_OUT=demo/out vpcopilot console` (no keys needed). See [DEMO.md](DEMO.md).

---

## Path B — Mitigate live behind F5 XC

This turns the recommendations into real, validated protection and closes the loop. You need:

- an **F5 Distributed Cloud** tenant: `XC_API_URL`, `XC_API_TOKEN`, `XC_NAMESPACE` in `.env`
- a **domain you control** to front the app (the examples use `*.banknimbus.com` — substitute your own)
- a `GITHUB_TOKEN` (or `gh auth login`) to open code-fix PRs

### 1. Stand up a clean test LB for the app

Run the app somewhere reachable (e.g. `docker compose up` on a box), then:

```bash
vpcopilot lab-create --domain vampi.example.com --origin <app-host>:5000
```
This creates an origin pool + a clean-slate HTTP LB and prints the **DNS records to add**. Once DNS
resolves and the cert issues, the app is reachable through XC at `https://vampi.example.com`.

### 2. Scan, then run the flow in the console

```bash
vpcopilot console
```
Set the **Load balancer** and **Validate URL** in *Run settings* to your lab LB + URL, then:

- **③ Mitigate** — click *Mitigate* on a finding. With dry-run **off**, the copilot attaches the
  band-aid, fires the finding's real exploit, refines until it's actually blocked, and shows
  `before 200 → after 403 BLOCKED`. Leave *keep live* off to auto-roll-back after validating
  (a safe smoke), or on to keep it enforcing.
- **④ Cure** — set a *PR repo* you can push to, then *Open PR* to draft the code fix.
- **⑤ Retire** — once the cure merges, *Retire* detaches the temporary XC control.

The equivalent CLI is in [USAGE.md](USAGE.md) (`apply --from-scan …`, `pr …`, `retire …`).

### Safety rails (always on)

- `scan` never writes anywhere; only `apply` / `pr` / `retire` touch live systems, and only behind
  the console/CLI human gate.
- Every apply **snapshots** the LB, self-tests the write, validates, and **rolls back on failure**
  (or when you don't pass *keep live*).
- Protected LBs (`VPCOPILOT_PROTECTED_LBS`, default `nimbus-www`) and `nimbus-*` policies refuse
  mutation unless you explicitly opt in.
- Want to be extra-careful validating an unfamiliar app? Set `VPCOPILOT_REQUIRE_PROBE=1` so a
  finding with no derived exploit probe is reported as *not validated* instead of guessed.

---

## Then: your own repo

It's the same command — `vpcopilot scan /path/to/your-repo` (or the **① Scan** step). Review the
findings safely first; only go to Path B when you're ready to protect a real app behind XC.
