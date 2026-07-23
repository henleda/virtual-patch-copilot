import { NextResponse } from 'next/server';
import { pool } from '@/lib/db';
import { getCurrentCustomer } from '@/lib/session';

// Safe, parameterized money movement between the customer's OWN accounts,
// inside a single DB transaction. Not an injection point.
export async function POST(request) {
  const customer = await getCurrentCustomer();
  if (!customer) {
    return NextResponse.json({ ok: false, error: 'Not signed in' }, { status: 401 });
  }

  let body;
  try {
    body = await request.json();
  } catch {
    body = {};
  }
  const fromId = Number(body.from_account);
  const toId = Number(body.to_account);
  const amount = Number(body.amount);

  if (!Number.isInteger(fromId) || !Number.isInteger(toId)) {
    return NextResponse.json({ ok: false, error: 'Choose both accounts' }, { status: 400 });
  }
  if (fromId === toId) {
    return NextResponse.json({ ok: false, error: 'Choose two different accounts' }, { status: 400 });
  }
  if (!(amount > 0)) {
    return NextResponse.json({ ok: false, error: 'Enter an amount greater than zero' }, { status: 400 });
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // Lock both accounts and confirm they belong to this customer.
    const { rows: accts } = await client.query(
      `SELECT id, balance FROM accounts
        WHERE id = ANY($1::int[]) AND customer_id = $2
        FOR UPDATE`,
      [[fromId, toId], customer.id]
    );
    if (accts.length !== 2) {
      await client.query('ROLLBACK');
      return NextResponse.json(
        { ok: false, error: 'Both accounts must be your own' },
        { status: 400 }
      );
    }

    const from = accts.find((a) => a.id === fromId);
    if (Number(from.balance) < amount) {
      await client.query('ROLLBACK');
      return NextResponse.json({ ok: false, error: 'Insufficient funds' }, { status: 400 });
    }

    await client.query('UPDATE accounts SET balance = balance - $1 WHERE id = $2', [amount, fromId]);
    await client.query('UPDATE accounts SET balance = balance + $1 WHERE id = $2', [amount, toId]);
    await client.query(
      'INSERT INTO transfers (from_account, to_account, amount) VALUES ($1, $2, $3)',
      [fromId, toId, amount]
    );

    await client.query('COMMIT');
    return NextResponse.json({ ok: true });
  } catch (err) {
    await client.query('ROLLBACK');
    return NextResponse.json({ ok: false, error: err.message }, { status: 500 });
  } finally {
    client.release();
  }
}
