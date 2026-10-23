'use strict';
/* x402 payment gate — identical terms to server.js.
 * $0.01 USDC on Base, payTo 0x6573682faee72a4a96e791ba262439f1df3a268d.
 * No payment -> 402 + accepts[]. Bad/unverifiable payment -> 402 fail-closed.
 * FREE_MODE=true bypasses (local testing only — NEVER on a public deploy).
 */

const PAY_TO = process.env.PAYMENT_ADDRESS || '0x6573682faee72a4a96e791ba262439f1df3a268d';
const PRICE_USDCENTS = process.env.PRICE_USDCENTS || '10000'; // $0.01 USDC, 6dp
const BASE_USDC = '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913';
const FACILITATOR_URL = process.env.X402_FACILITATOR_URL || 'https://x402.org/facilitator';
const FREE_MODE = process.env.FREE_MODE === 'true';

function publicBase() {
  return (process.env.PUBLIC_BASE_URL || '').replace(/\/$/, '');
}

function paymentRequirements(path) {
  return {
    scheme: 'exact',
    network: 'base',
    maxAmountRequired: PRICE_USDCENTS,
    resource: (process.env.X402_RESOURCE_URL || (publicBase() + path)).replace(/\/$/, '') || undefined,
    description: 'Approval Risk Auditor — full wallet approval audit: live ERC-20/ERC-721/operator approvals, UNLIMITED + STALE flags, revoke calldata.',
    mimeType: 'application/json',
    payTo: PAY_TO,
    maxTimeoutSeconds: 300,
    asset: BASE_USDC,
    extra: { name: 'USDC', version: '2' },
  };
}

function paymentRequiredBody(reason, path) {
  return {
    x402Version: 1,
    error: 'payment_required',
    ...(reason ? { reason } : {}),
    accepts: [paymentRequirements(path)],
  };
}

async function fetchTimeout(url, opts = {}, ms = 15000) {
  const c = new AbortController();
  const t = setTimeout(() => c.abort(), ms);
  try { return await fetch(url, { ...opts, signal: c.signal }); }
  finally { clearTimeout(t); }
}

async function verifyPayment(headerValue, path) {
  let payload;
  try {
    payload = JSON.parse(Buffer.from(headerValue, 'base64').toString('utf8'));
  } catch { return { ok: false, reason: 'malformed X-PAYMENT header' }; }
  try {
    const res = await fetchTimeout(FACILITATOR_URL + '/verify', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        x402Version: 1,
        paymentPayload: payload,
        paymentRequirements: paymentRequirements(path),
      }),
    }, 15000);
    if (!res.ok) return { ok: false, reason: 'facilitator unreachable (http ' + res.status + ')' };
    const j = await res.json();
    if (j.isValid) return { ok: true, payer: j.payer || null };
    return { ok: false, reason: j.invalidReason || 'payment invalid' };
  } catch (e) {
    return { ok: false, reason: 'facilitator unreachable: ' + (e.message || e) };
  }
}

// Express/Vercel-style gate: returns null when the request may proceed,
// otherwise {status, body} to send.
async function gate(req, path) {
  if (FREE_MODE) return null;
  const header = req.headers['x-payment'] || req.headers['X-PAYMENT'];
  if (!header) return { status: 402, body: paymentRequiredBody(null, path) };
  const v = await verifyPayment(header, path);
  if (!v.ok) return { status: 402, body: paymentRequiredBody(v.reason, path) };
  return { payer: v.payer };
}

module.exports = { gate, paymentRequirements, paymentRequiredBody, verifyPayment, FREE_MODE, PAY_TO, PRICE_USDCENTS, BASE_USDC };
