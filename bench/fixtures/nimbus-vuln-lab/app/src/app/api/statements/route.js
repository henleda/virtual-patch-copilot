import { NextResponse } from 'next/server';
import { query } from '@/lib/db';
import { getCurrentCustomer } from '@/lib/session';

// ============================================================================
// INTENTIONALLY VULNERABLE — DO NOT FIX.
// The statement search is the second injection point in the Nimbus demo
// (see CLAUDE.md). The query selects a single text column and is built by
// string concatenation on purpose so the UNION exfiltration payload
//   q = ' UNION SELECT username || ':' || password FROM customers --
// returns every customer's credentials. Protection is shown OUTSIDE the app
// by F5 XC. Do not parameterize, sanitize, escape, or validate `q`.
// ============================================================================

export async function GET(request) {
  // Auth is enforced (the exfil attack is the AUTHENTICATED one) — the session
  // lookup itself is safe and parameterized.
  const customer = await getCurrentCustomer();
  if (!customer) {
    return NextResponse.json({ ok: false, error: 'Not signed in' }, { status: 401 });
  }

  // accountId is the session customer's checking account. Safe lookup.
  const acct = await query(
    `SELECT id FROM accounts WHERE customer_id = $1 AND type = 'checking' ORDER BY id LIMIT 1`,
    [customer.id]
  );
  const accountId = acct.rows[0]?.id;

  const { searchParams } = new URL(request.url);
  const q = searchParams.get('q') ?? '';

  // VULNERABLE: raw string concatenation of both accountId and q. Intentional.
  const sql = `SELECT description FROM statements WHERE account_id = ${accountId} AND description ILIKE '%${q}%'`;

  let rows;
  try {
    ({ rows } = await query(sql));
  } catch (err) {
    return NextResponse.json({ ok: false, error: err.message, sql }, { status: 400 });
  }

  return NextResponse.json({
    ok: true,
    results: rows.map((r) => r.description),
    sql,
  });
}
