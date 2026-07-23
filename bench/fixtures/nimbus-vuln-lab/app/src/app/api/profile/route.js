import { NextResponse } from 'next/server';
import { pool } from '@/lib/db';
import { getCurrentCustomer } from '@/lib/session';

// vuln-lab ONLY (never deployed). INTENTIONAL: mass assignment. The update is built from
// whatever keys the client sends, with no allowlist of updatable columns, so an attacker
// can set fields they should never control (e.g. role, account_type, or even balance via
// a related table). Values are parameterized; the flaw is that client keys become columns.
export async function PATCH(request) {
  const customer = await getCurrentCustomer();
  if (!customer) {
    return NextResponse.json({ ok: false, error: 'Not signed in' }, { status: 401 });
  }
  let body;
  try { body = await request.json(); } catch { body = {}; }
  const keys = Object.keys(body);
  if (keys.length === 0) {
    return NextResponse.json({ ok: false, error: 'nothing to update' }, { status: 400 });
  }

  // BUG: no allowlist — every key in the request body becomes a column to update.
  const sets = keys.map((k, i) => `${k} = $${i + 1}`).join(', ');
  const values = keys.map((k) => body[k]);
  values.push(customer.id);
  const { rows } = await pool.query(
    `UPDATE customers SET ${sets} WHERE id = $${keys.length + 1}
       RETURNING id, username, full_name, email`,
    values
  );
  return NextResponse.json({ ok: true, profile: rows[0] });
}
