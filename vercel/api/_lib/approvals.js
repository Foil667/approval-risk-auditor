'use strict';
/* Approval enumeration module — zero dependencies, fetch-only.
 * Discovers a wallet's ERC-20 / ERC-721 / operator approvals from explorer
 * logs, verifies them live via eth_call, flags UNLIMITED + STALE, and builds
 * revoke calldata. Shared by server.js (/audit) and the Vercel handler.
 */

const TOPIC_APPROVAL = '0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925'; // Approval(address,address,uint256)
const TOPIC_APPROVAL_FOR_ALL = '0x17307eab39ab6107e8899845ad6d59fad0527ad09b7b0b939c5c1cca0e05dd'; // ApprovalForAll(address,address,bool)
const SEL_ALLOWANCE = '0xdd62ed3e';       // allowance(address,address)
const SEL_IS_APPROVED_FOR_ALL = '0xe985e9c5'; // isApprovedForAll(address,address)
const SEL_GET_APPROVED = '0x081812fc';    // getApproved(uint256)
const SEL_SYMBOL = '0x95d89b41';           // symbol()
const SEL_DECIMALS = '0x313ce567';        // decimals()
const SEL_APPROVE = '0x095ea7b3';         // approve(address,uint256) — also ERC-721 approve(address,uint256)
const SEL_SET_APPROVAL_FOR_ALL = '0xa22cb465'; // setApprovalForAll(address,bool)
const MAX_UINT256 = (1n << 256n) - 1n;
const ZERO_ADDR = '0x0000000000000000000000000000000000000000';
const STALE_DAYS = 180;
const MAX_LOG_PAGES = 2;       // per topic, per range (oldest + newest passes)
const LOG_PAGE_SIZE = 1000;
const MAX_PAIRS = 500;         // cap unique (token,spender) pairs live-checked per chain
const MAX_STALE_CHECKS = 15;   // legacy cap (superseded by risk-prioritized MAX_STALE in auditApprovals)
const BATCH_CHUNK = 40;        // eth_call batch chunk size (public RPC friendly)
const CONC = 6;                // concurrency for per-token metadata calls
const NEWEST_WINDOW = 2000000; // blocks (~1y on Ethereum) for the newest-first discovery pass

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
function padTopic(addr) { return '0x' + '0'.repeat(24) + addr.toLowerCase().slice(2); }
function pad32(hexOrBig) {
  let h = typeof hexOrBig === 'bigint' ? hexOrBig.toString(16) : String(hexOrBig).replace(/^0x/, '');
  return h.padStart(64, '0');
}
function wordToAddress(word) { return '0x' + word.toLowerCase().slice(-40); }
function isValidAddress(a) { return /^0x[0-9a-fA-F]{40}$/.test(a); }

async function fetchTimeout(url, opts = {}, ms = 15000) {
  const c = new AbortController();
  const t = setTimeout(() => c.abort(), ms);
  try { return await fetch(url, { ...opts, signal: c.signal }); }
  finally { clearTimeout(t); }
}

async function rpcBatch(rpcs, calls) {
  // calls: [{method, params}] -> results[] (throws on total failure)
  const chunks = [];
  for (let i = 0; i < calls.length; i += BATCH_CHUNK) chunks.push(calls.slice(i, i + BATCH_CHUNK));
  const out = [];
  for (const chunk of chunks) {
    const payload = chunk.map((c, i) => ({ jsonrpc: '2.0', id: i + 1, method: c.method, params: c.params }));
    let lastErr = new Error('no rpc');
    for (const url of rpcs) {
      try {
        const res = await fetchTimeout(url, {
          method: 'POST', headers: { 'content-type': 'application/json' },
          body: JSON.stringify(payload),
        }, 25000);
        if (!res.ok) throw new Error('http ' + res.status);
        const arr = await res.json();
        if (!Array.isArray(arr)) throw new Error('bad batch response');
        out.push(...arr.map((r) => {
          if (r.error) throw new Error(r.error.message || 'rpc error');
          return r.result;
        }));
        lastErr = null;
        break;
      } catch (e) { lastErr = e; }
    }
    if (lastErr) throw lastErr;
  }
  return out;
}

function decodeString(hex) {
  // minimal ABI decode of a dynamic string return
  try {
    if (!hex || hex === '0x') return null;
    const h = hex.slice(2);
    const len = parseInt(h.slice(64, 128), 16);
    if (!isFinite(len) || len <= 0 || len > 64) return null;
    const bytes = [];
    for (let i = 0; i < len * 2; i += 2) bytes.push(parseInt(h.slice(128 + i, 128 + i + 2), 16));
    const s = Buffer.from(bytes).toString('utf8').replace(/[^\x20-\x7e]/g, '');
    return s || null;
  } catch { return null; }
}

/* ---------------- log discovery ---------------- */
// Tries: (1) Etherscan V2 (if ETHERSCAN_API_KEY set — works for every chain),
// (2) chain's Blockscout /api getLogs (keyless). Returns {logs, source} or throws.
async function discoverLogs(chain, wallet) {
  const walletTopic = padTopic(wallet);
  const key = process.env.ETHERSCAN_API_KEY;
  const tryUrls = [];
  if (key) {
    tryUrls.push({
      source: 'etherscan-v2',
      base: `https://api.etherscan.io/v2/api?chainid=${chain.chainId}&module=logs&action=getLogs&apikey=${key}`,
    });
  }
  if (chain.logsApi) {
    tryUrls.push({ source: 'blockscout', base: chain.logsApi + '?module=logs&action=getLogs' });
  }
  const errors = [];
  for (const { source, base } of tryUrls) {
    try {
      const all = [];
      // Two passes: oldest-first (fromBlock=0) AND newest-first (recent window),
      // because the explorer paginates ascending and active wallets overflow one pass.
      let latestBlock = null;
      try {
        const br = await fetchTimeout(base + '?module=block&action=eth_block_number', {}, 10000);
        const bj = await br.json();
        if (bj.result) latestBlock = parseInt(bj.result, 16);
      } catch { /* newest pass skipped */ }
      const ranges = [{ from: '0', to: 'latest' }];
      if (latestBlock && latestBlock > NEWEST_WINDOW) {
        ranges.push({ from: '0x' + (latestBlock - NEWEST_WINDOW).toString(16), to: 'latest' });
      }
      for (const { from, to } of ranges) {
        for (const topic0 of [TOPIC_APPROVAL, TOPIC_APPROVAL_FOR_ALL]) {
          for (let page = 1; page <= MAX_LOG_PAGES; page++) {
            const url = `${base}&topic0=${topic0}&topic0_1_opr=and&topic1=${walletTopic}` +
              `&fromBlock=${from}&toBlock=${to}&page=${page}&offset=${LOG_PAGE_SIZE}`;
            const r = await fetchTimeout(url, {}, 30000);
            const ct = (r.headers.get('content-type') || '');
            if (!ct.includes('json')) throw new Error(source + ' non-json (walled?)');
            const j = await r.json();
            if (j.status !== '1' || !Array.isArray(j.result)) {
              if (/no records|not found/i.test(j.message || '') || (j.result && j.result.length === 0)) break;
              throw new Error(source + ': ' + (j.message || 'bad response'));
            }
            all.push(...j.result);
            if (j.result.length < LOG_PAGE_SIZE) break;
            await sleep(250);
          }
        }
      }
      // newest-first ordering so the pair cap keeps the most relevant pairs
      all.sort((a, b) => {
        const ba = parseInt(a.blockNumber || '0', 16), bb = parseInt(b.blockNumber || '0', 16);
        return bb - ba;
      });
      return { logs: all, source, truncated: all.length >= MAX_LOG_PAGES * LOG_PAGE_SIZE * 4 };
    } catch (e) { errors.push(source + ': ' + (e.message || e)); }
  }
  const err = new Error('log discovery unavailable: ' + errors.join(' | '));
  err.code = 'DISCOVERY_UNAVAILABLE';
  throw err;
}

function dedupePairs(logs) {
  const erc20 = new Map();   // token:spender -> {token, spender}
  const erc721 = new Map();  // token:tokenId -> {token, tokenId}
  const operators = new Map(); // token:operator -> {token, operator}
  for (const l of logs) {
    const topics = l.topics || [];
    const token = (l.address || '').toLowerCase();
    if (!isValidAddress(token) || topics.length < 3) continue;
    const t0 = (topics[0] || '').toLowerCase();
    if (t0 === TOPIC_APPROVAL.toLowerCase()) {
      // Blockscout pads ERC-20 Approval topics to 4 slots with a null 4th entry.
      // Robust discriminator: ERC-20 carries the value in `data` (32 bytes);
      // ERC-721 carries tokenId in topics[3] with empty data.
      const hasValue = l.data && l.data !== '0x' && l.data.length > 10;
      const t3 = topics[3];
      if (!hasValue && t3) {
        // ERC-721: Approval(owner, approved, tokenId)
        const approved = wordToAddress(topics[2]);
        let tokenId = null;
        try { tokenId = BigInt(t3).toString(); } catch { tokenId = null; }
        if (approved !== ZERO_ADDR && tokenId !== null) erc721.set(token + ':' + tokenId, { token, tokenId });
      } else {
        // ERC-20: Approval(owner, spender, value)
        const spender = wordToAddress(topics[2]);
        if (spender !== ZERO_ADDR) erc20.set(token + ':' + spender, { token, spender });
      }
    } else if (t0 === TOPIC_APPROVAL_FOR_ALL.toLowerCase() && topics.length >= 3 && topics[2]) {
      const operator = wordToAddress(topics[2]);
      if (operator !== ZERO_ADDR) operators.set(token + ':' + operator, { token, operator });
    }
  }
  return {
    erc20: [...erc20.values()].slice(0, MAX_PAIRS),
    erc721: [...erc721.values()].slice(0, MAX_PAIRS),
    operators: [...operators.values()].slice(0, MAX_PAIRS),
  };
}

/* ---------------- live verification ---------------- */
async function checkAllowances(chain, wallet, pairs) {
  // returns [{token, spender, allowance: bigint}]
  if (!pairs.length) return [];
  const calls = pairs.map((p) => ({
    method: 'eth_call',
    params: [{ to: p.token, data: SEL_ALLOWANCE + padTopic(wallet).slice(2) + padTopic(p.spender).slice(2) }, 'latest'],
  }));
  const results = await rpcBatch(chain.rpcs, calls);
  return pairs.map((p, i) => {
    let allowance = 0n;
    try { allowance = BigInt(results[i] || '0x0'); } catch { /* keep 0 */ }
    return { ...p, allowance };
  }).filter((x) => x.allowance > 0n);
}

async function checkNftApprovals(chain, wallet, pairs) {
  // per-tokenId ERC-721 approvals: live getApproved(tokenId)
  if (!pairs.length) return [];
  const calls = pairs.map((p) => ({
    method: 'eth_call',
    params: [{ to: p.token, data: SEL_GET_APPROVED + pad32(BigInt(p.tokenId)) }, 'latest'],
  }));
  const results = await rpcBatch(chain.rpcs, calls).catch(() => pairs.map(() => null));
  return pairs.map((p, i) => {
    let approved = null;
    try { if (results[i]) approved = wordToAddress(results[i]); } catch { /* skip */ }
    return { ...p, approved };
  }).filter((x) => x.approved && x.approved !== ZERO_ADDR);
}

async function checkOperators(chain, wallet, pairs) {
  if (!pairs.length) return [];
  const calls = pairs.map((p) => ({
    method: 'eth_call',
    params: [{
      to: p.token,
      data: SEL_IS_APPROVED_FOR_ALL + padTopic(wallet).slice(2) + padTopic(p.operator).slice(2),
    }, 'latest'],
  }));
  const results = await rpcBatch(chain.rpcs, calls).catch(() => pairs.map(() => null));
  return pairs.map((p, i) => {
    let active = false;
    try { active = results[i] && BigInt(results[i]) !== 0n; } catch { /* skip */ }
    return { ...p, active: !!active };
  }).filter((x) => x.active);
}

async function tokenMeta(chain, tokens) {
  // {token: {symbol, decimals}} — best effort, batched
  const out = {};
  const uniq = [...new Set(tokens)].slice(0, MAX_STALE_CHECKS * 2);
  if (!uniq.length) return out;
  const calls = [];
  uniq.forEach((t) => {
    calls.push({ method: 'eth_call', params: [{ to: t, data: SEL_SYMBOL }, 'latest'] });
    calls.push({ method: 'eth_call', params: [{ to: t, data: SEL_DECIMALS }, 'latest'] });
  });
  const results = await rpcBatch(chain.rpcs, calls).catch(() => []);
  uniq.forEach((t, i) => {
    const sym = decodeString(results[i * 2]);
    let dec = null;
    try { const d = results[i * 2 + 1]; if (d) dec = Number(BigInt(d)); if (!isFinite(dec) || dec > 36) dec = null; } catch { /* */ }
    out[t] = { symbol: sym, decimals: dec };
  });
  return out;
}

function formatAmount(raw, decimals) {
  if (raw === MAX_UINT256) return 'unlimited';
  if (decimals === null || decimals === undefined) return raw.toString();
  const s = raw.toString().padStart(decimals + 1, '0');
  const int = s.slice(0, -decimals) || '0';
  const frac = s.slice(-decimals).replace(/0+$/, '');
  return frac ? `${int}.${frac}` : int;
}

// Latest transfer involving wallet for a token (for STALE). Uses explorer
// account tokentx/tokennfttx (Etherscan-compat), sort=desc, offset=1.
async function latestInteraction(chain, wallet, token, isNft) {
  const key = process.env.ETHERSCAN_API_KEY;
  const bases = [];
  if (key) bases.push(`https://api.etherscan.io/v2/api?chainid=${chain.chainId}&apikey=${key}`);
  if (chain.logsApi) bases.push(chain.logsApi);
  for (const base of bases) {
    try {
      const action = isNft ? 'tokennfttx' : 'tokentx';
      const url = `${base}?module=account&action=${action}&address=${wallet}&contractaddress=${token}` +
        `&page=1&offset=1&sort=desc`;
      const r = await fetchTimeout(url, {}, 15000);
      const ct = r.headers.get('content-type') || '';
      if (!ct.includes('json')) continue;
      const j = await r.json();
      const items = j.result;
      if (Array.isArray(items) && items.length) {
        const ts = Number(items[0].timeStamp);
        if (isFinite(ts) && ts > 0) return new Date(ts * 1000).toISOString();
      }
      return null; // no transfers found -> treat as stale-eligible
    } catch { /* try next source */ }
  }
  return undefined; // unknown
}

async function mapConc(items, fn, conc = CONC) {
  const out = [];
  for (let i = 0; i < items.length; i += conc) {
    out.push(...await Promise.all(items.slice(i, i + conc).map(fn)));
  }
  return out;
}

/* ---------------- revoke calldata ---------------- */
function revokeErc20(token, spender) {
  return { to: token, data: SEL_APPROVE + pad32(spender) + '0'.repeat(64) };
}
function revokeErc721(token, tokenId) {
  return { to: token, data: SEL_APPROVE + '0'.repeat(64) + pad32(BigInt(tokenId)) };
}
function revokeOperator(token, operator) {
  // setApprovalForAll(operator, false)
  return { to: token, data: SEL_SET_APPROVAL_FOR_ALL + pad32(operator) + '0'.repeat(64) };
}

/* ---------------- main audit ---------------- */
async function auditApprovals(chainCfg, wallet, opts = {}) {
  const notes = [];
  const started = Date.now();
  let logs = [], source = null, discovery = 'full', truncated = false;
  try {
    const d = await discoverLogs(chainCfg, wallet);
    logs = d.logs; source = d.source; truncated = d.truncated;
    if (truncated) notes.push(`log discovery hit pagination caps (${logs.length} logs fetched) — some historical approvals may be missed; newest-first ordering keeps the most relevant pairs`);
  } catch (e) {
    if (e.code === 'DISCOVERY_UNAVAILABLE') {
      return {
        chain: chainCfg.name, chainId: chainCfg.chainId, discovery: 'unavailable',
        approvals: [], revoke_tx_data: [],
        stats: { pairs_discovered: 0, active_approvals: 0, unlimited: 0, stale: 0 },
        notes: ['approval log discovery unavailable on this network from here (no explorer key, RPC log ranges blocked) — set ETHERSCAN_API_KEY for full coverage'],
        ms: Date.now() - started,
      };
    }
    throw e;
  }

  const pairs = dedupePairs(logs);
  const totalPairs = pairs.erc20.length + pairs.erc721.length + pairs.operators.length;

  // live verification (batched)
  const [live20, live721, liveOps] = await Promise.all([
    checkAllowances(chainCfg, wallet, pairs.erc20),
    checkNftApprovals(chainCfg, wallet, pairs.erc721),
    checkOperators(chainCfg, wallet, pairs.operators),
  ]);

  const tokens = [...new Set([
    ...live20.map((x) => x.token), ...live721.map((x) => x.token), ...liveOps.map((x) => x.token),
  ])];
  const meta = await tokenMeta(chainCfg, tokens).catch(() => ({}));

  // staleness: prioritize highest-risk tokens (unlimited first, then by allowance),
  // capped to keep the endpoint fast
  const MAX_STALE = 40;
  const riskOrder = (t) => {
    let mx = 0n, unl = false;
    for (const x of live20) if (x.token === t) { if (x.allowance === MAX_UINT256) unl = true; if (x.allowance > mx) mx = x.allowance; }
    for (const x of liveOps) if (x.token === t) unl = true;
    return unl ? 2 : mx > 0n ? 1 : 0;
  };
  const staleTokens = [...tokens].sort((a, b) => riskOrder(b) - riskOrder(a)).slice(0, MAX_STALE);
  const lastTx = {};
  await mapConc(staleTokens, async (t) => {
    const isNft = live721.some((x) => x.token === t) || liveOps.some((x) => x.token === t);
    lastTx[t] = await latestInteraction(chainCfg, wallet, t, isNft);
  });
  const staleCutoff = Date.now() - STALE_DAYS * 86400000;

  const approvals = [];
  const push = (a) => approvals.push(a);
  for (const x of live20) {
    const m = meta[x.token] || {};
    const flags = [];
    if (x.allowance === MAX_UINT256) flags.push('UNLIMITED');
    const li = lastTx[x.token];
    if (li && new Date(li).getTime() < staleCutoff) flags.push('STALE');
    else if (li === null) flags.push('STALE');
    push({
      token: x.token, token_symbol: m.symbol || null, kind: 'erc20',
      spender: x.spender,
      allowance: x.allowance.toString(),
      allowance_human: formatAmount(x.allowance, m.decimals),
      risk_flags: flags,
      last_interaction: li || null,
      revoke: revokeErc20(x.token, x.spender),
    });
  }
  for (const x of live721) {
    const m = meta[x.token] || {};
    const flags = ['NFT_TOKEN_APPROVAL'];
    const li = lastTx[x.token];
    if (li && new Date(li).getTime() < staleCutoff) flags.push('STALE');
    else if (li === null) flags.push('STALE');
    push({
      token: x.token, token_symbol: m.symbol || null, kind: 'erc721',
      spender: x.approved, token_id: x.tokenId,
      allowance: '1', allowance_human: 'token #' + x.tokenId,
      risk_flags: flags,
      last_interaction: li || null,
      revoke: revokeErc721(x.token, x.tokenId),
    });
  }
  for (const x of liveOps) {
    const m = meta[x.token] || {};
    const flags = ['UNLIMITED_OPERATOR'];
    const li = lastTx[x.token];
    if (li && new Date(li).getTime() < staleCutoff) flags.push('STALE');
    else if (li === null) flags.push('STALE');
    push({
      token: x.token, token_symbol: m.symbol || null, kind: 'operator',
      spender: x.operator,
      allowance: 'unlimited', allowance_human: 'all tokens (ApprovalForAll)',
      risk_flags: flags,
      last_interaction: li || null,
      revoke: revokeOperator(x.token, x.operator),
    });
  }

  // order: riskiest first
  const rank = (a) => (a.risk_flags.includes('UNLIMITED') || a.risk_flags.includes('UNLIMITED_OPERATOR') ? 0 : a.risk_flags.includes('STALE') ? 1 : 2);
  approvals.sort((a, b) => rank(a) - rank(b));

  const stats = {
    pairs_discovered: totalPairs,
    active_approvals: approvals.length,
    unlimited: approvals.filter((a) => a.risk_flags.includes('UNLIMITED') || a.risk_flags.includes('UNLIMITED_OPERATOR')).length,
    stale: approvals.filter((a) => a.risk_flags.includes('STALE')).length,
  };
  if (source) notes.push('log source: ' + source);
  return {
    chain: chainCfg.name, chainId: chainCfg.chainId, discovery,
    approvals,
    revoke_tx_data: approvals.map((a) => ({ ...a.revoke, token: a.token, spender: a.spender, kind: a.kind })),
    stats, notes,
    ms: Date.now() - started,
  };
}

module.exports = {
  auditApprovals, revokeErc20, revokeErc721, revokeOperator,
  TOPIC_APPROVAL, TOPIC_APPROVAL_FOR_ALL, MAX_UINT256, STALE_DAYS, isValidAddress,
};
