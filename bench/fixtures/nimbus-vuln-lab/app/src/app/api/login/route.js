import { NextResponse } from 'next/server';
import { query } from '@/lib/db';
import { setSessionCookie } from '@/lib/session';

// ============================================================================
// INTENTIONALLY VULNERABLE — DO NOT FIX.
// This SQL injection is the entire point of the Nimbus demo (see CLAUDE.md).
// The login query is built by string concatenation on purpose so the
// auth-bypass payload  username = ' OR '1'='1' --  signs in with no credentials.
// Protection is demonstrated OUTSIDE the app by F5 XC, never in here.
// Do not parameterize, sanitize, escape, or validate these inputs.
// ============================================================================

export async function POST(request) {
  let body;
  try {
    body = await request.json();
  } catch {
    body = {};
  }
  const username = body.username ?? '';
  const password = body.password ?? '';

  // VULNERABLE: raw string concatenation. Intentional for the demo.
  const sql = `SELECT id, full_name, username FROM customers WHERE username = '${username}' AND password = '${password}'`;

  let rows;
  try {
    ({ rows } = await query(sql));
  } catch (err) {
    // Surface the DB error so the demo console can show what the injection did.
    return NextResponse.json(
      { ok: false, error: err.message, sql },
      { status: 400 }
    );
  }

  if (rows.length === 0) {
    return NextResponse.json(
      { ok: false, error: 'Invalid username or password', sql },
      { status: 401 }
    );
  }

  // The query returns the first matching row; issue a session for that customer.
  const customer = rows[0];
  setSessionCookie(customer.id);

  return NextResponse.json({
    ok: true,
    customer: { id: customer.id, full_name: customer.full_name, username: customer.username },
    sql,
  });
}
