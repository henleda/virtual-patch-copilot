import { NextResponse } from 'next/server';
import { query } from '@/lib/db';
import { getCurrentCustomer } from '@/lib/session';

// vuln-lab ONLY (never deployed). INTENTIONAL: IDOR / broken object-level authorization.
// Returns transactions for ANY account_id from the query string without verifying the
// account belongs to the signed-in customer. An attacker enumerates account_id to read
// every customer's transactions. The query is parameterized — the flaw is the missing
// ownership check, not SQLi.
export async function GET(request) {
  const customer = await getCurrentCustomer();
  if (!customer) {
    return NextResponse.json({ ok: false, error: 'Not signed in' }, { status: 401 });
  }
  const { searchParams } = new URL(request.url);
  const accountId = Number(searchParams.get('account_id'));
  if (!Number.isInteger(accountId)) {
    return NextResponse.json({ ok: false, error: 'account_id required' }, { status: 400 });
  }
  // BUG: no check that accountId belongs to customer.id.
  const { rows } = await query(
    `SELECT id, account_id, posted_at, description, amount
       FROM statements WHERE account_id = $1 ORDER BY posted_at DESC LIMIT 50`,
    [accountId]
  );
  return NextResponse.json({ ok: true, account_id: accountId, transactions: rows });
}
