# Restrict customer data exposure in API response

The endpoint was previously returning the entire customer object, which could expose sensitive information such as email, address, or other personal details. This posed a risk of sensitive data exposure if an attacker accessed the endpoint.

The fix involves modifying the response to only include non-sensitive fields from the customer object, specifically the `id` and `name`. This change ensures that sensitive information is not inadvertently exposed through the API.

This change permanently addresses the issue currently mitigated by a temporary XC virtual patch, which can be retired once this fix is merged.
