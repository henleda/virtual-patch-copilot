# Add ownership check for account_id in transactions API

The vulnerability in the transactions API allowed fetching transactions for any account_id specified in the query string without verifying that the account belongs to the signed-in customer. This could be exploited by an attacker to enumerate account_id values and access transactions of other customers.

The fix involves adding a check to ensure that the accountId belongs to the signed-in customer before proceeding to fetch transactions. This is done by querying the accounts table to verify the ownership of the accountId.

This change permanently remediates the issue currently held closed by a temporary XC virtual patch, which can be retired once this merge is complete.
