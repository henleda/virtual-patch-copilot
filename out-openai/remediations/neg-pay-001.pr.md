# Reject non-positive amounts in /api/pay

The application contained a business logic flaw that allowed transferring a negative amount, effectively reversing the flow of money. This could be exploited by an attacker to debit the payee's account and credit the sender's account, leading to potential theft.

The fix involves adding a guard clause to ensure that the amount specified in the transfer request is greater than zero. This prevents negative amounts from being processed, thereby maintaining the intended flow of money.

This change permanently remediates the issue currently mitigated by a temporary XC virtual patch, which can be retired once this fix is merged.
