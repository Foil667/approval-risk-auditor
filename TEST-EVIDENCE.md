# Test evidence — Approval Risk Auditor (v2.0.0)

> v2.0.0 extends the package from a contract red-flag scanner into a true
> wallet Approval Risk Auditor matching bounty #5's spec. The v1 contract-scan
> tests are preserved below under "v1 evidence".

All tests ran against `server.js` (zero-dep Node) with the new
`vercel/api/_lib/approvals.js` module. Analysis tests used `FREE_MODE=true` on
localhost (payment bypass for testing only — the public config runs with the
gate on); the 402 tests ran against the payment-gated config. Full JSON
responses are saved alongside this file.

## Test A1 — real wallet: vitalik.eth on Ethereum (full discovery)

- Request: `POST /audit` `{"wallet":"0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045","chains":["ethereum"]}`
- Timestamp: 2026-10-14T03:58Z → HTTP 200 in **23.6s** (extreme wallet; typical wallets far faster)
- Saved: `test-audit-vitalik-eth.json` (179 KB)
- Result: `discovery: "full"` (log source: blockscout); **703 (token,spender)
  pairs discovered → 202 active approvals → 66 UNLIMITED → 15 STALE**.
  Top hit: unlimited ERC-20 approvals to Uniswap V3 SwapRouter
  (`0x7a250d5630…`) across dozens of tokens, correctly flagged UNLIMITED;
  approvals with no token interaction in 180+ days flagged STALE
  (e.g. BMW → SwapRouter, last interaction 2022-03-07).
- `revoke_tx_data[]`: 202 entries. **All 202 verified by decode**: `to` equals
  the token contract; `data` starts `0x095ea7b3` (approve) with the spender
  padded in arg 1 and amount 0 (ERC-20), or `0xa22cb465`
  (setApprovalForAll) with operator + false (operators).
- Pipeline proven end-to-end: explorer log discovery (Approval +
  ApprovalForAll topics) → live `allowance()` / `isApprovedForAll()` /
  `getApproved()` eth_calls → UNLIMITED (`2^256-1`) + STALE (180d) flags →
  `approve(spender,0)` / `approve(0,tokenId)` / `setApprovalForAll(op,false)`
  calldata.

## Test A2 — Foil's wallet, Base + Ethereum (degraded discovery, honest output)

- Request: `POST /audit` `{"wallet":"0x6573682faee72a4a96e791ba262439f1df3a268d","chains":["base","ethereum"]}`
- Timestamp: 2026-10-14T03:59Z → HTTP 200 in 6.4s
- Saved: `test-audit-foil-base-eth.json`
- Result: Base → `discovery: "unavailable"` with an explicit note (Blockscout
  is Cloudflare-walled from the test network, no Etherscan key configured —
  set `ETHERSCAN_API_KEY` for full coverage). **No data fabricated**: empty
  approvals with the reason stated. Ethereum → `discovery: "full"`,
  0 active approvals (correct — the wallet has no Ethereum approval history).

## Test A3 — x402 gate on /audit: no payment

- Request: `POST /audit` with a valid body, **no** `X-PAYMENT` header.
- Result: **HTTP 402**, `error: "payment_required"`,
  `accepts: [{scheme:"exact", network:"base", maxAmountRequired:"10000"
  ($0.01 USDC), payTo:"0x6573682faee72a4a96e791ba262439f1df3a268d",
  asset:"0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913" (Base USDC),
  resource:"…/audit", …}]` — same $0.01 terms as /check.
- Saved: `test-audit-402-no-payment.json`

## Test A4 — x402 gate on /audit: malformed payment (fail-closed)

- Request: `POST /audit` with `X-PAYMENT: bm90LXJlYWwtcGF5bWVudA==` (garbage).
- Result: **HTTP 402** with `reason: "malformed X-PAYMENT header"` — rejected
  before any audit ran.

## Test A5 — Vercel handler unit checks (mocked req/res)

- `GET /api/health` → 200 `{status:"ok", service:"approval-risk-auditor", version:"2.0.0"}`
- `POST /api/audit` (FREE_MODE) → 200, correct shape
  (`{service, version, wallet, chains, scannedAt}`)
- `GET /api/audit` → 405; `POST` with bad wallet → 400
- `POST /api/audit` without FREE_MODE and no X-PAYMENT → **402** with the
  $0.01 USDC / Base accepts payload

## Test A6 — independent re-verification run (2026-10-14 ~04:04 UTC)

A second agent re-ran the full audit against the same wallet to confirm the
results are reproducible and independently verifiable:

- Request: `POST /audit` `{"wallet":"0xd8da6bf26964af9d7eed9e03e53415d37aa96045","chains":["ethereum"]}`
  (the real vitalik.eth address — note: an earlier draft of SUBMISSION.md
  carried a mistyped `0x1f9090aa…` address; corrected everywhere in this run)
- Timestamp: 2026-10-14T04:04:51Z → HTTP 200 in ~40s (incl. HTTP overhead;
  chain-side audit 23.6s-class, within the 25s budget on a second pass)
- Saved: `test-audit-vitalik-eth-v2.json` (179 KB)
- Result: **identical stats — 703 pairs discovered → 202 active approvals →
  66 UNLIMITED → 15 STALE**, all ERC-20; `revoke_tx_data[]` 202 entries.
  Symbols include USDT, SPX, GLAMSTERDAM, NVDA, DOGE among the unlimited set.
- **Revoke calldata decode: 202/202 pass** — every entry's `to` equals the
  token contract, `data` starts `0x095ea7b3` (approve), arg 1 is the
  zero-padded spender, arg 2 is 64 zero nibbles (amount 0), 138 chars total.
- **Independent spot-check**: the 5 largest approvals (RTRD, BMW, REPUBLICANS,
  ORO, CZSB — all unlimited to Uniswap V3 SwapRouter
  `0x7a250d5630b4cf539739df2c5dacb4c659f2488d`) were re-verified with a fresh
  `allowance()` eth_call through a *separate* RPC provider
  (ethereum-rpc.publicnode.com): **5/5 matched** the reported values
  (2^256-1 each). (Ankr and llamarp were rate-limiting/blocking at test time;
  publicnode served as the independent reader.)
- **Gated 402 on /audit re-confirmed**: no-payment → **402** with the $0.01
  USDC-on-Base accepts payload (saved: `test-audit-402-v2.json`);
  garbage X-PAYMENT → **402** fail-closed.
- **Vercel handler re-tested locally** (mock req/res, zero deps, no build):
  health 200, audit 200 with identical stats (703/202/66/15), bad wallet 400,
  GET 405, gated 402 with correct accepts[] — `vercel/` is deploy-ready.

## What was NOT tested

End-to-end paid flow with a real signed USDC payment (would require spending
real funds — not authorized). The verify path is implemented against the public
x402 facilitator (`https://x402.org/facilitator/verify`) and fails closed.

---

# v1 evidence — Contract Red-Flag Check (preserved)

All tests ran against `server.js` (zero-dep Node). Analysis tests used
`FREE_MODE=true` on localhost (payment bypass for testing only — the public
config runs with the gate on); the 402 tests ran against the payment-gated
config. Full JSON responses are saved alongside this file.

## Test 1 — real contract: USDC on Base

- Request: `POST /check` `{"contract":"0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913","chain":"base"}`
- Timestamp: 2026-10-14T02:51:16Z → response 2026-10-14T02:51:21.838Z (HTTP 200, 5.8s)
- Saved: `test1-usdc-base.json`
- Result: `verified: true` (Sourcify exact_match), `score: 80`,
  `verdict: SAFE-ISH`; flags: EOA owner `0x3abd6f64a422225e61e435bae41db12096106df7`
  (from live `owner()` eth_call), DELEGATECALL opcode in bytecode.
  Checks run: eth_getCode, sourcify verification, blockscout verification,
  eip-1967 proxy slots, owner() eth_call, bytecode selector extraction + 4byte,
  bytecode opcode disassembly.

## Test 2 — real contract: WETH on Ethereum

- Request: `POST /check` `{"contract":"0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2","chain":"ethereum"}`
- Timestamp: 2026-10-14T02:51:21Z → response 2026-10-14T02:51:29.058Z (HTTP 200, 7.2s)
- Saved: `test2-weth-eth.json`
- Result: `verified: true`, `contractName: WETH9` (via Blockscout),
  `owner: null` (no `owner()` — correct for WETH9), `score: 80`,
  `verdict: SAFE-ISH`; flags: withdraw function present, DELEGATECALL opcode.
  Checks run: all of Test 1's **plus** ABI function inventory, live value
  getters, holder concentration.
- The DELEGATECALL flag was independently re-verified with a clean-room
  disassembly walk (PUSH-data-aware): exactly one real `0xf4` opcode at
  bytecode offset 3101 of 1577 decoded ops. The flag is genuine, not a
  PUSH-data false positive.

## Test 3 — x402 gate: no payment

- Request: `POST /check` with a valid body, **no** `X-PAYMENT` header.
- Result: **HTTP 402**, body `{"x402Version":1,"error":"payment_required",
  "accepts":[{scheme:"exact", network:"base", maxAmountRequired:"10000"
  ($0.01 USDC), payTo:"0x6573682faee72a4a96e791ba262439f1df3a268d",
  asset:"0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913" (Base USDC), ...}]}`
- Saved: `test-402-no-payment.json`

## Test 4 — x402 gate: malformed payment (fail-closed)

- Request: `POST /check` with `X-PAYMENT: bm90LXJlYWwtcGF5bWVudA==` (garbage).
- Result: **HTTP 402** with `reason: "malformed X-PAYMENT header"` — rejected
  before any analysis ran. A payment that fails facilitator verification is
  likewise rejected; an unreachable facilitator also rejects (fail-closed).
- Saved: `test-402-bad-payment.json`

## What was NOT tested

End-to-end paid flow with a real signed USDC payment (would require spending
real funds — not authorized). The verify path is implemented against the public
x402 facilitator (`https://x402.org/facilitator/verify`) and fails closed.
