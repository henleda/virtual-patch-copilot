# Security policy

## Authorized use only

virtual-patch-copilot is a **dual-use security tool**. Its `scan` step is read-only and safe, but the
`apply` / `pr` / `retire` steps make real changes to load balancers and repositories, and validation
fires real exploits at a target.

Only run it against applications and infrastructure that **you own or are explicitly authorized to
test**. You are responsible for how you use it.

Built-in guardrails help but are not a substitute for authorization:

- `scan` never writes to any live system.
- Every apply snapshots the LB, self-tests the write, validates, and rolls back on failure.
- Protected LBs (`VPCOPILOT_PROTECTED_LBS`) and `nimbus-*` policies refuse mutation unless explicitly
  overridden.
- Secrets come from the environment / a local `.env` (never commit real credentials or tenant IDs).

## Reporting a vulnerability

If you find a security issue in this project, please **do not open a public issue**. Instead, report
it privately via GitHub's "Report a vulnerability" (Security Advisories) on the repository, or by
opening a minimal private channel with the maintainers. We'll acknowledge and work on a fix; please
allow reasonable time before any public disclosure.
