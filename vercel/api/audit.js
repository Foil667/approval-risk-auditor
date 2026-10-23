'use strict';
/* POST /api/audit — Approval Risk Auditor (Daydreams bounty #5).
 * Input:  { wallet: "0x...", chains: ["ethereum","base"], include_contract_scan?: bool }
 * Output: { wallet, chains: { <chain>: { approvals[], revoke_tx_data[], stats, notes } } }
 * x402-gated: $0.01 USDC on Base. No X-PAYMENT -> 402 + accepts[].
 * Zero dependencies. Stateless. No local ports.
 */

const { gate, FREE_MODE, PAY_TO } = require('./_lib/x402');
const { auditApprovals, isValidAddress } = require('./_lib/approvals');

const CHAIN_CONFIG = {
  ethereum: {
    name: 'Ethereum', chainId: 1,
    rpcs: ['https://ethereum-rpc.publicnode.com', 'https://eth.llamarpc.com', 'https://rpc.ankr.com/eth'],
    logsApi: 'https://eth.blockscout.com/api',
  },
  base: {
    name: 'Base', chainId: 8453,
    rpcs: ['https://mainnet.base.org', 'https://base-rpc.publicnode.com'],
    logsApi: 'https://base.blockscout.com/api', // may be CF-walled from some networks; ETHERSCAN_API_KEY unlocks full coverage
  },
};

const VERSION = '2.0.0';

function send(res, status, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'access-control-allow-origin': '*',
  });
  res.end(body);
}

module.exports = async (req, res) => {
  if (req.method === 'OPTIONS') {
    res.writeHead(204, {
      'access-control-allow-origin': '*',
      'access-control-allow-headers': 'content-type, x-payment',
      'access-control-allow-methods': 'POST, OPTIONS',
    });
    return res.end();
  }
  if (req.method !== 'POST') {
    return send(res, 405, { error: 'POST only', usage: { wallet: '0x...', chains: ['ethereum', 'base'] } });
  }

  let body = req.body;
  if (typeof body === 'string') {
    try { body = JSON.parse(body); } catch { return send(res, 400, { error: 'invalid JSON body' }); }
  }
  body = body || {};
  const wallet = String(body.wallet || '').trim();
  if (!isValidAddress(wallet)) return send(res, 400, { error: 'wallet must be a 0x address (40 hex chars)' });
  let chains = body.chains;
  if (!chains) chains = ['ethereum', 'base'];
  if (!Array.isArray(chains)) return send(res, 400, { error: 'chains must be an array' });
  chains = [...new Set(chains.map((c) => String(c).toLowerCase()))].filter((c) => CHAIN_CONFIG[c]);
  if (!chains.length) return send(res, 400, { error: 'no supported chains requested', supported: Object.keys(CHAIN_CONFIG) });

  // ---- x402 gate (unchanged terms) ----
  const g = await gate(req, '/api/audit');
  if (g && g.status) return send(res, g.status, g.body);
  const payer = g && g.payer ? g.payer : null;

  // ---- audit ----
  const out = {};
  const errors = {};
  await Promise.all(chains.map(async (c) => {
    try {
      out[c] = await auditApprovals(CHAIN_CONFIG[c], wallet.toLowerCase());
    } catch (e) {
      errors[c] = String((e && e.message) || e).slice(0, 300);
    }
  }));

  const result = {
    service: 'approval-risk-auditor',
    version: VERSION,
    wallet: wallet.toLowerCase(),
    chains: out,
    scannedAt: new Date().toISOString(),
  };
  if (Object.keys(errors).length) result.chain_errors = errors;
  if (payer) result.x402 = { paid: true, payer };
  else if (FREE_MODE) result.x402 = { paid: false, free_mode: true };
  return send(res, 200, result);
};
