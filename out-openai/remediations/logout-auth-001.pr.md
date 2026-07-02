# Add CSRF protection to logout endpoint

The logout endpoint was vulnerable to CSRF attacks, allowing attackers to log out users without their consent by tricking them into making a POST request to the endpoint. This fix introduces CSRF protection by verifying a CSRF token in the request. If the token is invalid or missing, the request is rejected with a 403 status. This change permanently addresses the issue currently mitigated by a temporary XC virtual patch, which can be retired once this fix is merged.
