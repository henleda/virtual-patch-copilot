# Implement allowlist to prevent mass assignment in PATCH endpoint

This PR addresses a high-severity mass assignment vulnerability in the PATCH endpoint of the `profile/route.js` file. The vulnerability allowed attackers to update sensitive fields in the 'customers' table by crafting a JSON request with arbitrary keys, which were directly mapped to database columns without validation.

### Vulnerability Details
The existing code did not restrict which fields could be updated, allowing any field specified in the request body to be updated in the database. This included sensitive fields such as 'role', 'account_type', and 'balance'.

### Exploit
An attacker could exploit this by sending a JSON payload with keys corresponding to sensitive fields, thereby altering data they should not have access to.

### Fix
The fix introduces an allowlist of fields that can be updated: `username`, `full_name`, and `email`. Only these fields are now allowed to be updated, preventing unauthorized modification of sensitive fields.

This change permanently remediates the issue currently mitigated by a temporary XC virtual patch, which can be retired once this fix is merged.
