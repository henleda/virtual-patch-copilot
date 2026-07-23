import { NextResponse } from 'next/server';
import { getCurrentCustomer } from '@/lib/session';

// vuln-lab ONLY (never deployed). INTENTIONAL: SSRF. Fetches a user-supplied URL
// server-side with no scheme/host allowlist and no internal-address blocking, so an
// attacker can reach internal services and the cloud metadata endpoint
// (http://169.254.169.254/latest/meta-data/...) and exfiltrate credentials.
export async function POST(request) {
  const customer = await getCurrentCustomer();
  if (!customer) {
    return NextResponse.json({ ok: false, error: 'Not signed in' }, { status: 401 });
  }
  let body;
  try { body = await request.json(); } catch { body = {}; }
  const url = String(body.url ?? '');
  if (!url) {
    return NextResponse.json({ ok: false, error: 'url required' }, { status: 400 });
  }

  // BUG: no allowlist, no scheme/host validation, no SSRF guard against internal ranges.
  const resp = await fetch(url);
  const contentType = resp.headers.get('content-type') || '';
  const data = await resp.text();
  return NextResponse.json({
    ok: true,
    content_type: contentType,
    bytes: data.length,
    preview: data.slice(0, 256),
  });
}
