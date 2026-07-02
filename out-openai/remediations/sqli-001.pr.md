# Sanitize 'q' parameter to prevent SQL injection

The 'q' parameter in the SQL query was directly concatenated into the SQL statement without any sanitization, leading to a critical SQL injection vulnerability. An attacker could exploit this by manipulating the 'q' parameter to inject arbitrary SQL code, potentially exfiltrating sensitive data such as usernames and passwords.

This fix introduces basic sanitization by escaping single quotes in the 'q' parameter, preventing the injection of malicious SQL code. This change permanently addresses the issue currently mitigated by an F5 XC virtual patch, which can be retired once this fix is merged.
