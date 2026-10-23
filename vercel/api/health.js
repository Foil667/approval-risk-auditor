'use strict';
/* GET /api/health — no payment required. */

const { FREE_MODE, PAY_TO, PRICE_USDCENTS } = require('./_lib/x402');

module.exports = async (req, res) => {
  const body = JSON.stringify({
    status: 'ok',
    service: 'approval-risk-auditor',
    version: '2.0.0',
    chains: ['ethereum', 'base'],
    x402: { required: !FREE_MODE, network: 'base', asset: 'USDC', priceUsd: '0.01', payTo: PAY_TO },
    price_usdcents: PRICE_USDCENTS,
    time: new Date().toISOString(),
  });
  res.writeHead(200, {
    'content-type': 'application/json; charset=utf-8',
    'access-control-allow-origin': '*',
  });
  res.end(body);
};
