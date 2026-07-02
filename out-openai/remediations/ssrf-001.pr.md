# Implement URL allowlist to prevent SSRF in avatar route

The application was vulnerable to a Server-Side Request Forgery (SSRF) attack due to unvalidated URL fetching in the `avatar/route.js` file. This allowed attackers to supply URLs pointing to internal services or cloud metadata endpoints, potentially leading to sensitive data exposure.

The vulnerability was addressed by implementing a host allowlist, which restricts URL fetching to a predefined set of trusted hosts. This ensures that only URLs from these hosts are processed, effectively mitigating the SSRF risk.

This change permanently remediates the issue currently held closed by a temporary XC virtual patch, which can be retired once this merge is complete.
