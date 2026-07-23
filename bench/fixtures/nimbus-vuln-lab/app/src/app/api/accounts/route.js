import { NextResponse } from 'next/server';
import { query } from '@/lib/db';
import { getCurrentCustomer } from '@/lib/session';

export async function GET() {
  const customer = await getCurrentCustomer();
  if (!customer) {
    return NextResponse.json({ ok: false, error: 'Not signed in' }, { status: 401 });
  }
  // Safe, parameterized.
  const { rows } = await query(
    `SELECT id, type, number, balance
       FROM accounts
      WHERE customer_id = $1
      ORDER BY id`,
    [customer.id]
  );
  return NextResponse.json({ ok: true, accounts: rows });
}
