'use strict';
/* Contract Red-Flag Check — x402-gated onchain contract risk scanner.
 * Read-only: no wallet, no signatures, no spending. Zero dependencies.
 *
 * GET  /                          landing page
 * GET  /health                     health check (no payment)
 * GET  /.well-known/x402.json      x402 discovery (no payment)
 * POST /check  {contract, chain}   full scan — requires x402 payment (402 otherwise)
 */

const http = require('http');
const { randomUUID } = require('crypto');
const { auditApprovals, isValidAddress: isValidWallet } = require('./vercel/api/_lib/approvals');

/* ---------------- config ---------------- */
const PORT = Number(process.env.PORT || 8787);
const PUBLIC_BASE_URL = (process.env.PUBLIC_BASE_URL || `http://localhost:${PORT}`).replace(/\/$/, '');
const FREE_MODE = process.env.FREE_MODE === 'true'; // local testing only — NEVER on the public deploy
const FACILITATOR_URL = process.env.X402_FACILITATOR_URL || 'https://x402.org/facilitator';
const PAY_TO = (process.env.PAYMENT_ADDRESS || '0x6573682faee72a4a96e791ba262439f1df3a268d');
const PRICE_USDCENTS = process.env.PRICE_USDCENTS || '10000'; // $0.01 USDC, 6 decimals
const BASE_USDC = '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913';
const SERVICE = 'contract-red-flag-check';
const VERSION = '1.0.0';

const CHAINS = {
  base: {
    name: 'Base', chainId: 8453,
    rpcs: ['https://mainnet.base.org', 'https://base-rpc.publicnode.com'],
    api: 'https://base.blockscout.com/api/v2',
    explorer: 'https://base.blockscout.com',
  },
  ethereum: {
    name: 'Ethereum', chainId: 1,
    rpcs: ['https://ethereum-rpc.publicnode.com', 'https://eth.llamarpc.com', 'https://rpc.ankr.com/eth'],
    api: 'https://eth.blockscout.com/api/v2',
    explorer: 'https://eth.blockscout.com',
  },
  robinhood: {
    name: 'Robinhood Chain', chainId: 4663,
    rpcs: ['https://rpc.mainnet.chain.robinhood.com'],
    api: 'https://robinhoodchain.blockscout.com/api/v2',
    explorer: 'https://robinhoodchain.blockscout.com',
  },
};

const ZERO = '0x0000000000000000000000000000000000000000';
const IMPL_SLOT = '0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc';
const BEACON_SLOT = '0xa3f0ad74e5423aebfd80d3ef4346578335f4e408abc8f2a3fd5d7b4d078b902de';
const EIP1167_PREFIX = '363d3d373d3d3d363d73';
const EIP1167_SUFFIX = '5af43d82803e903d91602b57fd5bf3';
const SEL_OWNER = '0x8da5cb5b';
const SEL_TOTALSUPPLY = '0x18160ddd';

const KNOWN_SELS = {
  '8da5cb5b': 'owner()', '18160ddd': 'totalSupply()', '313ce567': 'decimals()',
  '5c975abb': 'paused()', '06fdde03': 'name()', '95d89b41': 'symbol()',
  '70a08231': 'balanceOf(address)', 'a9059cbb': 'transfer(address,uint256)',
  '23b872dd': 'transferFrom(address,address,uint256)', '095ea7b3': 'approve(address,uint256)',
  'dd62ed3e': 'allowance(address,address)', '06f9e0d3': 'implementation()',
  '715018a6': 'renounceOwnership()', 'f2fde38b': 'transferOwnership(address)',
  '8f70ccf6': 'tradingEnabled()', 'a0b8e49c': 'tradingActive()',
  '8456cb59': 'pause()', '3f4ba83a': 'unpause()',
  'e2bbb158': 'maxTxAmount()', '4f8e027a': 'maxWalletAmount()',
  '7d0c9a84': '_maxTxAmount()', 'f2c6d3b5': '_maxWalletAmount()',
};

const VALUE_GETTERS = [
  'maxtxamount', '_maxtxamount', 'maxwalletamount', 'maxwallet', '_maxwallet',
  'buytax', '_buytax', 'selltax', '_selltax', 'buyfee', 'sellfee', 'totalfee',
  'maxsupply', 'max_supply', 'mintprice', 'cost', 'price', 'publicprice', 'mintcost',
  'paused', 'tradingactive', 'tradingenabled', 'swapenabled', 'limitsineffect',
  'decimals',
];

/* ---------------- tiny utils ---------------- */
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
function hexToBytes(h) {
  h = h.startsWith('0x') || h.startsWith('0X') ? h.slice(2) : h;
  const b = new Uint8Array(h.length / 2);
  for (let i = 0; i < b.length; i++) b[i] = parseInt(h.substr(i * 2, 2), 16);
  return b;
}
function bytesToHex(b) { return [...b].map((x) => x.toString(16).padStart(2, '0')).join(''); }
function wordToAddress(word) { return '0x' + word.toLowerCase().slice(-40); }
function shortAddr(a) { return a.slice(0, 6) + '…' + a.slice(-4); }
function isValidAddress(a) { return /^0x[0-9a-fA-F]{40}$/.test(a); }

async function fetchTimeout(url, opts = {}, ms = 15000) {
  const c = new AbortController();
  const t = setTimeout(() => c.abort(), ms);
  try { return await fetch(url, { ...opts, signal: c.signal }); }
  finally { clearTimeout(t); }
}

/* ---------------- rpc ---------------- */
async function rpcBatch(chain, calls) {
  const payload = calls.map((c, i) => ({ jsonrpc: '2.0', id: i + 1, method: c.method, params: c.params }));
  let lastErr = new Error('no rpc');
  for (const url of chain.rpcs) {
    try {
      const res = await fetchTimeout(url, {
        method: 'POST', headers: { 'content-type': 'application/json' },
        body: JSON.stringify(payload),
      }, 20000);
      if (!res.ok) throw new Error('http ' + res.status);
      const arr = await res.json();
      if (!Array.isArray(arr)) throw new Error('bad batch response');
      return arr.map((r) => {
        if (r.error) throw new Error(r.error.message || 'rpc error');
        return r.result;
      });
    } catch (e) { lastErr = e; }
  }
  throw lastErr;
}
const ethCall = (chain, addr, data) =>
  rpcBatch(chain, [{ method: 'eth_call', params: [{ to: addr, data }, 'latest'] }]).then((r) => r[0]);

/* ---------------- bytecode analysis ---------------- */
function extractSelectors(code) {
  const b = hexToBytes(code);
  const out = new Set();
  for (let i = 0; i + 6 < b.length; i++) {
    if (b[i] === 0x63 && b[i + 5] === 0x14) out.add(bytesToHex(b.slice(i + 1, i + 5)));
  }
  return [...out];
}
function scanOpcodes(code) {
  const b = hexToBytes(code);
  const found = { delegatecall: false, selfdestruct: false };
  for (let i = 0; i < b.length; i++) {
    const op = b[i];
    if (op >= 0x60 && op <= 0x7f) { i += op - 0x5f; continue; }
    if (op === 0xf4) found.delegatecall = true;
    if (op === 0xff) found.selfdestruct = true;
  }
  return found;
}
async function resolveSelectors(selectors) {
  const out = {};
  const unknown = [];
  for (const s of selectors) {
    if (KNOWN_SELS[s]) out[s] = [KNOWN_SELS[s]];
    else unknown.push(s);
  }
  const todo = unknown.slice(0, 60);
  const CONC = 8;
  for (let i = 0; i < todo.length; i += CONC) {
    await Promise.all(todo.slice(i, i + CONC).map(async (s) => {
      try {
        const r = await fetchTimeout('https://www.4byte.directory/api/v1/signatures/?hex_signature=0x' + s, {}, 10000);
        const j = await r.json();
        if (j.results && j.results.length) out[s] = j.results.map((x) => x.text_signature).slice(0, 8);
      } catch { /* best effort */ }
    }));
    await sleep(120);
  }
  return out;
}
function classifyName(name) {
  const n = name.toLowerCase();
  if (/(selfdestruct|suicide)/.test(n)) return 'kill';
  if (/blacklist/.test(n)) return 'blacklist';
  if (/^(set|update|change|adjust|toggle).*(tax|fee)/.test(n)) return 'taxsetter';
  if (/^(mint|airdrop)/.test(n)) return 'mint';
  if (/^(withdraw|rescue|sweep|recover|skim|clearstuck)/.test(n)) return 'drain';
  if (n === 'pause' || n === 'unpause' || n === 'setpaused') return 'pause';
  if (/^(renounceownership|transferownership)/.test(n)) return 'ownership';
  if (/^(maxtx|maxwallet|maxbuy|maxsell)/.test(n)) return 'limits';
  return null;
}
const selCache = {};
async function selectorFor(fnAbi) {
  const sig = fnAbi.name + '(' + (fnAbi.inputs || []).map((i) => i.type).join(',') + ')';
  if (selCache[sig]) return selCache[sig];
  try {
    const r = await fetchTimeout('https://www.4byte.directory/api/v1/signatures/?text_signature=' + encodeURIComponent(sig), {}, 10000);
    const j = await r.json();
    if (j.results && j.results.length) { selCache[sig] = j.results[0].hex_signature; return selCache[sig]; }
  } catch { /* fall through */ }
  return '0x00000000';
}
function decodeSingle(hex, type) {
  if (!hex || hex === '0x') return null;
  try {
    if (/^u?int/.test(type)) return BigInt(hex).toString();
    if (type === 'bool') return (BigInt(hex) !== 0n).toString();
    if (type === 'address') return wordToAddress(hex);
    if (type === 'string') return '(string)';
    return hex.slice(0, 66);
  } catch { return null; }
}

/* ---------------- the scan (ported 1:1 from the battle-tested browser checker) ---------------- */
async function scan(chainId, address) {
  const chain = CHAINS[chainId];
  const addr = address.toLowerCase();
  const flags = [];
  const notes = [];
  const reads = [];
  const checks = [];
  let score = 100;
  const hit = (sev, text, check, pts) => { flags.push({ sev, text, check }); if (pts) score -= pts; };
  const note = (sev, text, check) => notes.push({ sev, text, check });
  const ck = (name) => checks.push(name);

  const [code] = await rpcBatch(chain, [{ method: 'eth_getCode', params: [addr, 'latest'] }]);
  ck('eth_getCode');
  if (!code || code === '0x' || code === '0x0') return { notContract: true, chain: chain.name, addr };

  let verified = false, abi = null, contractName = null, verification = 'unknown';
  // Sourcify first (no key, no bot-wall); Blockscout second (often Cloudflare-walled).
  try {
    const r = await fetchTimeout(`https://sourcify.dev/server/v2/contract/${chain.chainId}/${addr}`, {}, 12000);
    if (r.ok) {
      const j = await r.json();
      if (j.match === 'exact_match' || j.match === 'match' || j.match === 'partial_match') {
        verified = true; verification = 'verified';
      }
    } else if (r.status === 404) { verification = 'unverified-sourcify'; }
  } catch { /* unreachable — stays unknown */ }
  ck('sourcify verification');
  try {
    const r = await fetchTimeout(chain.api + '/smart-contracts/' + addr, {}, 12000);
    if (r.ok) {
      const j = await r.json();
      if (j.is_verified) { verified = true; verification = 'verified'; }
      else if (verification === 'unverified-sourcify') verification = 'unverified';
      if (j.is_verified) { abi = Array.isArray(j.abi) ? j.abi : null; contractName = j.name || null; }
    } else if (r.status === 404 && verification === 'unverified-sourcify') { verification = 'unverified'; }
  } catch { /* explorer unreachable — treat as unknown, not unverified */ }
  ck('blockscout verification');
  if (verified) {
    note('good', 'source verified' + (contractName ? ' — ' + contractName : '') + '. you can read exactly what it does.', 'sourcify/blockscout: verified');
    if (contractName) reads.push(['contract name', contractName]);
  } else if (verification === 'unverified') {
    hit('high', 'source NOT verified. closed-source contract asking for your money — classic.', 'sourcify: no match, blockscout: not verified', 25);
  } else {
    note('info', 'source verification unavailable (explorers unreachable) — could not confirm verified source. treat with extra caution.', 'sourcify/blockscout unreachable');
  }

  let implAddr = null, beaconAddr = null, isMinimalProxy = null;
  try {
    const [implWord, beaconWord] = await rpcBatch(chain, [
      { method: 'eth_getStorageAt', params: [addr, IMPL_SLOT, 'latest'] },
      { method: 'eth_getStorageAt', params: [addr, BEACON_SLOT, 'latest'] },
    ]);
    if (implWord && !/^0x0+$/.test(implWord)) implAddr = wordToAddress(implWord);
    if (beaconWord && !/^0x0+$/.test(beaconWord)) beaconAddr = wordToAddress(beaconWord);
  } catch { /* non-fatal */ }
  ck('eip-1967 proxy slots');
  const codeNoPrefix = code.slice(2).toLowerCase();
  if (codeNoPrefix.startsWith(EIP1167_PREFIX) && codeNoPrefix.endsWith(EIP1167_SUFFIX)) {
    isMinimalProxy = '0x' + codeNoPrefix.slice(EIP1167_PREFIX.length, EIP1167_PREFIX.length + 40);
  }
  const isProxy = !!(implAddr || beaconAddr || isMinimalProxy);
  if (implAddr) reads.push(['proxy implementation', implAddr]);
  if (beaconAddr) reads.push(['proxy beacon', beaconAddr]);
  if (isMinimalProxy) reads.push(['minimal proxy →', isMinimalProxy]);
  if (isProxy) hit('med', 'upgradeable proxy. whoever controls upgrades can swap the code under you — treat owner as god-mode.', 'eip-1967 slots / eip-1167 bytecode', 0);
  else note('good', 'no standard proxy pattern (eip-1967/eip-1167) — probably not upgradeable via the usual routes.', 'eip-1967 slots empty, no eip-1167 bytecode');

  let owner = null, ownerKind = 'unknown';
  try {
    const ret = await ethCall(chain, addr, SEL_OWNER);
    if (ret && ret.length >= 42) {
      owner = wordToAddress(ret);
      if (owner === ZERO) ownerKind = 'renounced';
      else {
        const [ocode] = await rpcBatch(chain, [{ method: 'eth_getCode', params: [owner, 'latest'] }]);
        ownerKind = (ocode && ocode !== '0x' && ocode !== '0x0') ? 'contract' : 'eoa';
      }
    }
  } catch { /* no owner() — fine */ }
  ck('owner() eth_call');
  if (owner) {
    reads.push(['owner()', owner + (ownerKind === 'renounced' ? ' (renounced)' : ' (' + ownerKind + ')')]);
    if (ownerKind === 'renounced') note('good', 'ownership renounced (owner = 0x0). nobody holds the keys.', 'owner() → zero address');
    else if (ownerKind === 'eoa') hit('med', 'owned by a regular wallet (' + shortAddr(owner) + '). one person holds the keys.', 'owner() → eoa', 8);
    else if (ownerKind === 'contract') note('info', 'owned by a contract (' + shortAddr(owner) + ') — could be a multisig/dao, or could be another trap. verify it.', 'owner() → contract code present');
  } else {
    note('info', 'no owner() found — either ownable-free or custom access control. read the source.', 'eth_call owner() reverted/empty');
  }
  if (isProxy) {
    if (ownerKind === 'eoa') hit('high', 'proxy + eoa owner = one wallet can rewrite this contract at will.', 'proxy + owner()', 20);
    else if (ownerKind === 'contract') hit('med', 'proxy controlled by a contract — safer than an eoa, still upgradeable.', 'proxy + owner()', 10);
    else hit('med', 'proxy with unclear upgrade control. assume the worst.', 'proxy slots', 15);
  }

  let fnSigs = [];
  if (verified && abi) {
    fnSigs = abi.filter((e) => e.type === 'function').map((e) => e.name + '(' + (e.inputs || []).map((i) => i.type).join(',') + ')');
  } else {
    const sels = extractSelectors(code);
    const resolved = await resolveSelectors(sels);
    fnSigs = Object.values(resolved).flat();
  }
  ck(verified && abi ? 'abi function inventory' : 'bytecode selector extraction + 4byte');
  const kinds = {};
  for (const sig of fnSigs) {
    const nm = sig.split('(')[0];
    if (/^test/i.test(nm)) continue;
    const k = classifyName(nm);
    if (k) { (kinds[k] = kinds[k] || new Set()).add(nm); }
  }
  const has = (k) => kinds[k] && kinds[k].size > 0;
  const eoaOwner = ownerKind === 'eoa';
  if (has('kill')) hit('crit', 'self-destruct capability (' + [...kinds.kill].join(', ') + '). the dev can nuke it.', 'function name heuristic', 30);
  if (has('blacklist')) hit('high', 'blacklist functions (' + [...kinds.blacklist].join(', ') + '). wallets can be frozen out of selling.', 'function name heuristic', 15);
  if (has('taxsetter')) hit('med', 'owner-adjustable taxes/fees (' + [...kinds.taxsetter].join(', ') + '). rates can change after you buy.', 'function name heuristic', 12);
  if (has('mint')) {
    if (ownerKind === 'renounced') hit('low', 'mint functions exist (' + [...kinds.mint].join(', ') + ') but ownership is renounced.', 'function name heuristic', 4);
    else hit('med', 'mint functions (' + [...kinds.mint].join(', ') + ')' + (eoaOwner ? ' + eoa owner = supply can be printed on a whim.' : ' — check who can call them.'), 'function name heuristic', eoaOwner ? 12 : 8);
  }
  if (has('drain')) {
    if (ownerKind === 'renounced') note('info', 'withdraw/rescue-style functions exist but ownership is renounced.', 'function name heuristic');
    else hit('med', 'funds can be pulled via (' + [...kinds.drain].join(', ') + ')' + (eoaOwner ? ' by the eoa owner.' : ' — check access control.'), 'function name heuristic', 8);
  }
  if (has('pause')) note('info', 'pausable (' + [...kinds.pause].join(', ') + '). transfers can be halted — sometimes legit, sometimes not.', 'function name heuristic');
  if (has('limits')) note('info', 'transfer limits (' + [...kinds.limits].join(', ') + '). can be anti-whale… or anti-you.', 'function name heuristic');
  if (has('ownership')) note('info', 'ownership functions present (' + [...kinds.ownership].join(', ') + ').', 'function name heuristic');

  const ops = scanOpcodes(code);
  ck('bytecode opcode disassembly');
  if (ops.selfdestruct) hit('crit', 'SELFDESTRUCT opcode in bytecode. contract can destroy itself.', 'bytecode disassembly', 30);
  if (ops.delegatecall) hit('med', 'DELEGATECALL in bytecode. can run other contracts\' code in its own context.', 'bytecode disassembly', 12);

  if (verified && abi) {
    const fns = abi.filter((e) =>
      e.type === 'function' && (e.stateMutability === 'view' || e.stateMutability === 'pure') &&
      (e.inputs || []).length === 0 && (e.outputs || []).length === 1 &&
      VALUE_GETTERS.includes((e.name || '').toLowerCase())
    );
    const seen = new Set();
    const uniq = fns.filter((f) => { const k = f.name.toLowerCase(); return seen.has(k) ? false : (seen.add(k), true); }).slice(0, 14);
    try {
      const selList = await Promise.all(uniq.map(selectorFor));
      const calls = uniq.map((f, i) => ({ method: 'eth_call', params: [{ to: addr, data: selList[i] }, 'latest'] }));
      if (calls.length) {
        const rets = await rpcBatch(chain, calls);
        const vals = {};
        uniq.forEach((f, i) => {
          const v = decodeSingle(rets[i], f.outputs[0].type);
          if (v !== null) { vals[f.name.toLowerCase()] = v; reads.push([f.name + '()', v]); }
        });
        const taxOf = (v) => { const n = Number(v); if (!isFinite(n)) return null; if (n <= 100) return n; if (n <= 10000) return n / 100; return null; };
        const bt = taxOf(vals['buytax'] ?? vals['_buytax']);
        const st = taxOf(vals['selltax'] ?? vals['_selltax']);
        if (bt !== null || st !== null) {
          const total = (bt || 0) + (st || 0);
          if (total >= 25) hit('high', 'combined buy+sell tax ≈ ' + total + '% — honeypot math.', 'live tax getters', 15);
          else if (total >= 10) hit('med', 'combined buy+sell tax ≈ ' + total + '%. spicy.', 'live tax getters', 8);
          else note('good', 'combined tax ≈ ' + total + '% — reasonable.', 'live tax getters');
        }
        if (vals['paused'] === 'true') hit('med', 'contract is currently PAUSED. transfers are frozen.', 'paused()', 5);
        const ta = vals['tradingactive'] ?? vals['tradingenabled'];
        if (ta === 'false') note('info', 'trading is currently disabled.', 'tradingActive()/tradingEnabled()');
        ck('live value getters');
      }
    } catch { /* best effort */ }
  }

  try {
    const hr = await fetchTimeout(chain.api + '/tokens/' + addr + '/holders', {}, 12000);
    if (hr.ok) {
      const hj = await hr.json();
      const items = hj.items || [];
      if (items.length) {
        const ts = await ethCall(chain, addr, SEL_TOTALSUPPLY).catch(() => null);
        if (ts) {
          const total = BigInt(ts);
          if (total > 0n) {
            const top = items[0];
            const topVal = BigInt(top.value || '0');
            const pct = Number((topVal * 10000n) / total) / 100;
            const topAddr = ((top.address && top.address.hash) || '').toLowerCase();
            const isBurn = topAddr === ZERO || topAddr === '0x000000000000000000000000000000000000dead';
            reads.push(['top holder', shortAddr(top.address.hash) + ' — ' + pct.toFixed(1) + '% of supply']);
            if (!isBurn && pct > 50) hit('high', 'one wallet holds ' + pct.toFixed(1) + '% of supply. dump risk is real.', 'blockscout holders', 12);
            else if (!isBurn && pct > 20) note('info', 'top wallet holds ' + pct.toFixed(1) + '% of supply. keep an eye on it.', 'blockscout holders');
            else if (isBurn) note('good', 'biggest holder is the burn address — supply actually reduced.', 'blockscout holders');
            ck('holder concentration');
          }
        }
      }
    }
  } catch { /* best effort */ }

  score = Math.max(0, Math.min(100, score));
  const verdict = score >= 80 ? 'SAFE-ISH' : score >= 50 ? 'CAUTION' : 'AVOID';
  const order = { crit: 0, high: 1, med: 2, low: 3 };
  flags.sort((a, b) => (order[a.sev] ?? 4) - (order[b.sev] ?? 4));
  return {
    runId: randomUUID(), service: SERVICE, version: VERSION,
    chain: chain.name, chainId, contract: addr,
    verified, contractName, owner: owner ? { address: owner, kind: ownerKind } : null,
    proxy: isProxy ? { implementation: implAddr, beacon: beaconAddr, minimalProxyTarget: isMinimalProxy } : null,
    score, verdict, flags, notes, reads, checks, scannedAt: new Date().toISOString(),
  };
}

/* ---------------- x402 ---------------- */
function paymentRequirements(path, description) {
  return {
    scheme: 'exact',
    network: 'base',
    maxAmountRequired: PRICE_USDCENTS,
    // exact URL the payment covers (must match the real public endpoint)
    resource: process.env.X402_RESOURCE_URL || (PUBLIC_BASE_URL + (path || '/check')),
    description: description || 'Contract Red-Flag Check — full onchain risk scan of one EVM contract (score, flags, proxy/owner/tax reads).',
    mimeType: 'application/json',
    payTo: PAY_TO,
    maxTimeoutSeconds: 300,
    asset: BASE_USDC,
    extra: { name: 'USDC', version: '2' },
  };
}
const AUDIT_DESC = 'Approval Risk Auditor — full wallet approval audit: live ERC-20/ERC-721/operator approvals, UNLIMITED + STALE flags, revoke calldata.';
function paymentRequiredBody(reason, audit) {
  return {
    x402Version: 1,
    error: 'payment_required',
    ...(reason ? { reason } : {}),
    accepts: [paymentRequirements(audit ? '/audit' : '/check', audit ? AUDIT_DESC : undefined)],
  };
}
async function verifyPayment(headerValue, audit) {
  // headerValue: base64-encoded x402 payment payload (X-PAYMENT)
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
        paymentRequirements: paymentRequirements(audit ? '/audit' : '/check', audit ? AUDIT_DESC : undefined),
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

/* ---------------- http ---------------- */
const hits = new Map(); // ip -> [timestamps], tiny rate limiter for /check
function rateLimited(ip) {
  const now = Date.now();
  const arr = (hits.get(ip) || []).filter((t) => now - t < 60000);
  arr.push(now);
  hits.set(ip, arr);
  return arr.length > 20;
}
function send(res, status, obj, extraHeaders = {}) {
  const body = typeof obj === 'string' ? obj : JSON.stringify(obj);
  res.writeHead(status, {
    'content-type': typeof obj === 'string' ? 'text/html; charset=utf-8' : 'application/json; charset=utf-8',
    'access-control-allow-origin': '*',
    ...extraHeaders,
  });
  res.end(body);
}
function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', (c) => { data += c; if (data.length > 65536) { reject(new Error('body too large')); req.destroy(); } });
    req.on('end', () => resolve(data));
    req.on('error', reject);
  });
}

const LANDING = `<!doctype html><html><head><meta charset="utf-8"><title>Contract Red-Flag Check</title>
<style>body{font-family:system-ui;background:#0d0d0f;color:#e8e8e8;max-width:720px;margin:40px auto;padding:0 20px}
h1{color:#ccff00}a{color:#ccff00}code{background:#1c1c20;padding:2px 6px;border-radius:4px}
pre{background:#1c1c20;padding:12px;border-radius:8px;overflow-x:auto}</style></head><body>
<h1>🕵️ Contract Red-Flag Check</h1>
<p>Read-only onchain risk scan for EVM contracts. No wallet, no signatures, no spending — it only <em>reads</em>.</p>
<p><b>Chains:</b> Base, Ethereum, Robinhood Chain</p>
<p><b>Price:</b> $0.01 USDC on Base, paid via <a href="https://x402.org">x402</a></p>
<h3>Use it</h3>
<pre>curl -X POST ${'${PUBLIC}'}${'/check'} \\
  -H "Content-Type: application/json" \\
  -H "X-PAYMENT: &lt;base64 x402 payment payload&gt;" \\
  -d '{"contract":"0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913","chain":"base"}'</pre>
<p>No payment header? You'll get <code>402 Payment Required</code> with the exact payment terms.</p>
<p><a href="/health">health</a> · <a href="/.well-known/x402.json">x402 discovery</a></p>
</body></html>`.replace('${PUBLIC}', PUBLIC_BASE_URL).replace("${'/check'}", '/check');

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, 'http://x');
    const ip = req.socket.remoteAddress || 'unknown';

    if (req.method === 'GET' && url.pathname === '/') return send(res, 200, LANDING);
    if (req.method === 'GET' && url.pathname === '/health') {
      return send(res, 200, {
        status: 'ok', service: SERVICE, version: VERSION,
        chains: Object.keys(CHAINS),
        x402: { required: !FREE_MODE, network: 'base', asset: 'USDC', priceUsd: '0.01', payTo: PAY_TO },
        freeMode: FREE_MODE, time: new Date().toISOString(),
      });
    }
    if (req.method === 'GET' && url.pathname === '/.well-known/x402.json') {
      return send(res, 200, {
        x402Version: 1,
        name: SERVICE,
        description: 'Read-only onchain contract risk scanner. POST /check with {contract, chain} and an x402 payment.',
        endpoints: [{ path: '/check', method: 'POST', accepts: [paymentRequirements()] }],
      });
    }
    // NOTE: smee.io (free public relay) only forwards the channel root path,
    // so POST / is aliased to /check for the public deployment.
    if (req.method === 'POST' && (url.pathname === '/check' || url.pathname === '/')) {
      if (rateLimited(ip)) return send(res, 429, { error: 'rate_limited', retryAfterSeconds: 60 });
      let body;
      try { body = JSON.parse(await readBody(req)); }
      catch { return send(res, 400, { error: 'invalid JSON body' }); }
      const contract = String(body.contract || '').trim();
      const chain = String(body.chain || 'base').trim().toLowerCase();
      if (!isValidAddress(contract)) return send(res, 400, { error: 'contract must be a 0x address (40 hex chars)' });
      if (!CHAINS[chain]) return send(res, 400, { error: 'unknown chain', supported: Object.keys(CHAINS) });

      let payer = null;
      if (!FREE_MODE) {
        const payHeader = req.headers['x-payment'];
        if (!payHeader) return send(res, 402, paymentRequiredBody());
        const v = await verifyPayment(payHeader);
        if (!v.ok) return send(res, 402, paymentRequiredBody(v.reason));
        payer = v.payer;
      }
      try {
        const result = await scan(chain, contract);
        if (result.notContract) return send(res, 422, { error: 'no contract code at that address on ' + CHAINS[chain].name });
        if (payer) result.x402 = { paid: true, payer };
        return send(res, 200, result);
      } catch (e) {
        return send(res, 502, { error: 'scan failed', detail: String(e.message || e).slice(0, 300) });
      }
    }
    // POST /audit — Approval Risk Auditor (same x402 gate as /check)
    if (req.method === 'POST' && url.pathname === '/audit') {
      if (rateLimited(ip)) return send(res, 429, { error: 'rate_limited', retryAfterSeconds: 60 });
      let body;
      try { body = JSON.parse(await readBody(req)); }
      catch { return send(res, 400, { error: 'invalid JSON body' }); }
      const wallet = String(body.wallet || '').trim();
      if (!isValidWallet(wallet)) return send(res, 400, { error: 'wallet must be a 0x address (40 hex chars)' });
      let chains = body.chains || ['ethereum', 'base'];
      if (!Array.isArray(chains)) chains = ['ethereum', 'base'];
      chains = [...new Set(chains.map((c) => String(c).toLowerCase()))].filter((c) => CHAINS[c]);
      if (!chains.length) return send(res, 400, { error: 'no supported chains requested', supported: Object.keys(CHAINS) });

      let payer = null;
      if (!FREE_MODE) {
        const payHeader = req.headers['x-payment'];
        if (!payHeader) return send(res, 402, paymentRequiredBody(null, true));
        const v = await verifyPayment(payHeader, true);
        if (!v.ok) return send(res, 402, paymentRequiredBody(v.reason, true));
        payer = v.payer;
      }
      try {
        const out = {};
        const errors = {};
        await Promise.all(chains.map(async (c) => {
          const cfg = { name: CHAINS[c].name, chainId: CHAINS[c].chainId, rpcs: CHAINS[c].rpcs, logsApi: c === 'ethereum' ? 'https://eth.blockscout.com/api' : 'https://base.blockscout.com/api' };
          try { out[c] = await auditApprovals(cfg, wallet.toLowerCase()); }
          catch (e) { errors[c] = String((e && e.message) || e).slice(0, 300); }
        }));
        const result = { service: 'approval-risk-auditor', version: '2.0.0', wallet: wallet.toLowerCase(), chains: out, scannedAt: new Date().toISOString() };
        if (Object.keys(errors).length) result.chain_errors = errors;
        if (payer) result.x402 = { paid: true, payer };
        else if (FREE_MODE) result.x402 = { paid: false, free_mode: true };
        return send(res, 200, result);
      } catch (e) {
        return send(res, 502, { error: 'audit failed', detail: String(e.message || e).slice(0, 300) });
      }
    }
    return send(res, 404, { error: 'not found' });
  } catch (e) {
    return send(res, 500, { error: 'internal error' });
  }
});

server.listen(PORT, '127.0.0.1', () => {
  console.log(`${SERVICE} v${VERSION} listening on 127.0.0.1:${PORT} (public: ${PUBLIC_BASE_URL}) freeMode=${FREE_MODE}`);
});
