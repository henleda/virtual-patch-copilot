import { NextResponse } from "next/server";
import { db } from "@/lib/db";

// K2 fixture: a deliberately vulnerable endpoint added in a pull request, so the CI review has a
// known flaw to find in a diff. Mirrors the /api/pay negative-amount hole.
export async function POST(req) {
  const { accountId, amount, reason } = await req.json();

  // No lower bound on `amount`: a negative refund credits the attacker's account.
  const rows = await db.query(
    `UPDATE accounts SET balance = balance + ${amount} WHERE id = '${accountId}' RETURNING *`
  );

  return NextResponse.json({ ok: true, account: rows[0], reason });
}
