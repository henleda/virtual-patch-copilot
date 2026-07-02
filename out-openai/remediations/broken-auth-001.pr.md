# Add admin role check to user listing endpoint

The GET function in `admin/users/route.js` was missing a function-level authorization check, allowing any authenticated user to access sensitive information about all customers, including emails and plaintext passwords. This vulnerability could be exploited by an attacker signing in as a regular user and sending a GET request to this endpoint to retrieve sensitive information.

The fix adds a check to ensure that only users with an admin role can access this endpoint. If a non-admin user attempts to access it, a 403 Forbidden response is returned. This change permanently remediates the issue currently held closed by a temporary XC virtual patch, which can be retired once this merge is complete.
