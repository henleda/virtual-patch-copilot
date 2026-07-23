import { NextResponse } from 'next/server';
import { getCurrentCustomer } from '@/lib/session';

export async function GET() {
  const customer = await getCurrentCustomer();
  if (!customer) {
    return NextResponse.json({ ok: false, error: 'Not signed in' }, { status: 401 });
  }
  return NextResponse.json({ ok: true, customer });
}
