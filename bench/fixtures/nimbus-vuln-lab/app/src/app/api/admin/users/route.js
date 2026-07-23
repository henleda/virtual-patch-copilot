import { NextResponse } from 'next/server';
import { query } from '@/lib/db';
import { getCurrentCustomer } from '@/lib/session';

// vuln-lab ONLY (never deployed). INTENTIONAL: missing function-level authorization.
// Any signed-in customer (no admin/role check) can list EVERY customer, including emails
// and plaintext passwords. The endpoint authenticates but never authorizes.
export async function GET() {
  const customer = await getCurrentCustomer();
  if (!customer) {
    return NextResponse.json({ ok: false, error: 'Not signed in' }, { status: 401 });
  }
  // BUG: no role/admin check — any authenticated user reaches this admin endpoint.
  const { rows } = await query(
    'SELECT id, username, full_name, email, password FROM customers ORDER BY id'
  );
  return NextResponse.json({ ok: true, users: rows });
}
