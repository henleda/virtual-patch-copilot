import { NextResponse } from 'next/server';
import { query } from '@/lib/db';

// vuln-lab ONLY (never deployed). INTENTIONAL: no attempt throttling / lockout on OTP
// verification, so a short numeric code is brute-forceable (unlimited guesses, no delay,
// no per-user attempt counter). The lookup is parameterized — the flaw is the missing
// rate limiting / lockout.
export async function POST(request) {
  let body;
  try { body = await request.json(); } catch { body = {}; }
  const username = String(body.username ?? '');
  const code = String(body.code ?? '');

  // BUG: no attempt counter, no lockout, no backoff — an attacker can try every code.
  const { rows } = await query(
    'SELECT id FROM customers WHERE username = $1 AND otp_code = $2',
    [username, code]
  );
  if (rows.length === 1) {
    return NextResponse.json({ ok: true, verified: true });
  }
  return NextResponse.json({ ok: false, verified: false }, { status: 401 });
}
