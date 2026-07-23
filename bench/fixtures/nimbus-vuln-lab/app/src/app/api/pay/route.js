import { NextResponse } from 'next/server';
import { pool } from '@/lib/db';
import { getCurrentCustomer } from '@/lib/session';

// "Send money to another Nimbus customer." Fully parameterized (NOT a SQL-injection point).
// INTENTIONAL business-logic flaw for the demo: unlike /api/transfer it never checks
// `amount > 0`, so a negative amount reverses the flow — debiting the payee and crediting
// the sender (theft). A frontier model finds this by READING the code (a missing invariant);
// a signature WAF cannot (the request is valid); XC virtual-patches it with a positive-security
// service policy. Do not "fix" it.
//
// Payee is identified by account NUMBER (bank UI) or by account id (demo console).
export async function POST(request) {
  const customer = await getCurrentCustomer();
  if (!customer) {
    return NextResponse.json({ ok: false, error: 'Not signed in' }, { status: 401 });
  }

  let body;
  try { body = await request.json(); } catch { body = {}; }
  const fromId = Number(body.from_account);
  const amount = Number(body.amount); // <-- no `amount > 0` guard: the flaw
  const toNumber = (body.to_account_number ?? '').toString().trim();

  if (!Number.isInteger(fromId)) {
    return NextResponse.json({ ok: false, error: 'Choose a source account' }, { status: 400 });
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // Resolve the payee: by account number (UI) or by id (demo console).
    let toId = Number(body.to_account);
    if (toNumber) {
      const { rows } = await client.query('SELECT id FROM accounts WHERE number = $1', [toNumber]);
      if (rows.length !== 1) {
        await client.query('ROLLBACK');
        return NextResponse.json({ ok: false, error: 'Payee account not found' }, { status: 400 });
      }
      toId = rows[0].id;
    }
    if (!Number.isInteger(toId) || fromId === toId) {
      await client.query('ROLLBACK');
      return NextResponse.json({ ok: false, error: 'Choose a valid payee' }, { status: 400 });
    }

    // Only the SOURCE must belong to you; sending to another customer is the feature.
    const { rows: src } = await client.query(
      'SELECT id, balance FROM accounts WHERE id = $1 AND customer_id = $2 FOR UPDATE',
      [fromId, customer.id]
    );
    if (src.length !== 1) {
      await client.query('ROLLBACK');
      return NextResponse.json({ ok: false, error: 'Source account not found' }, { status: 400 });
    }

    await client.query('UPDATE accounts SET balance = balance - $1 WHERE id = $2', [amount, fromId]);
    await client.query('UPDATE accounts SET balance = balance + $1 WHERE id = $2', [amount, toId]);
    await client.query(
      'INSERT INTO transfers (from_account, to_account, amount) VALUES ($1, $2, $3)',
      [fromId, toId, amount]
    );
    const { rows: after } = await client.query('SELECT balance FROM accounts WHERE id = $1', [fromId]);

    await client.query('COMMIT');
    return NextResponse.json({ ok: true, moved: amount, your_new_balance: Number(after[0].balance) });
  } catch (err) {
    await client.query('ROLLBACK');
    return NextResponse.json({ ok: false, error: err.message }, { status: 500 });
  } finally {
    client.release();
  }
}
