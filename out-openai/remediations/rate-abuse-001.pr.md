# Implement rate limiting on OTP verification endpoint

The OTP verification endpoint lacked rate limiting, allowing attackers to brute-force OTP codes by making unlimited guesses without any delay or penalty. This vulnerability could lead to unauthorized access if an attacker successfully guesses the correct OTP.

The fix introduces a rate limiting mechanism that restricts the number of OTP verification attempts to 5 requests per 15 minutes. This significantly reduces the risk of successful brute-force attacks by limiting the number of guesses an attacker can make in a given timeframe.

This change permanently addresses the issue currently mitigated by a temporary XC virtual patch, which can be retired once this fix is merged.
