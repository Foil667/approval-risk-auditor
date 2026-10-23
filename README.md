# Daydreams Bounty #5 — "Approval Risk Auditor" ($1,000): Entry Package (HELD — NOT SUBMITTED)

**Status as of 2026-10-14 ~04:00 UTC:** Bounty is **OPEN** (verified, see BOUNTY-STATUS.md).
The entry is **built, tested, and packaged** — but **nothing has been submitted anywhere**.
No PR opened, no registration, no posting. Awaiting the user's explicit go-ahead.

## What was built (v2.0.0)

**Approval Risk Auditor** — a read-only wallet approval auditor, x402-gated,
zero dependencies (pure Node.js). Matches bounty #5's spec:

- `POST /api/audit` `{wallet, chains}` → live approval set: ERC-20 allowances,
  ERC-721 per-token approvals, ApprovalForAll operators — each with
  `risk_flags` (`UNLIMITED` / `STALE`) and a ready `revoke_tx_data[]` entry.
  Chains: Ethereum, Base.
- Discovery: explorer Approval/ApprovalForAll logs (Etherscan V2 with
  `ETHERSCAN_API_KEY`, Blockscout keyless), every pair re-verified live via
  `allowance()` / `getApproved()` / `isApprovedForAll()`.
- x402: `$0.01` USDC on Base per audit, `payTo 0x6573682faee72a4a96e791ba262439f1df3a268d`.
  No payment → `402` + `accepts[]`. Bad payment → `402` fail-closed.
- `GET /api/health`, `GET /.well-known/x402.json`.
- Vercel-ready: `vercel/` (`api/audit.js`, `api/health.js`, `vercel.json`,
  `public/.well-known/x402.json`) — zero deps, no build step, stateless.
- The original contract red-flag scan remains (`POST /check` in `server.js`).

## What is proven (evidence in this folder)

1. **Real approval audit, not a stub** — vitalik.eth on Ethereum:
   703 pairs discovered → **202 live approvals, 66 UNLIMITED, 15 STALE**
   (23.6s, test-audit-vitalik-eth.json). All 202 revoke calldata entries
   verified by decoding (selector, spender padding, zero amount).
2. **Honest degradation** — Base from the test network: `discovery:
   "unavailable"` with the reason stated, zero fabricated data
   (test-audit-foil-base-eth.json). Set `ETHERSCAN_API_KEY` for full coverage.
3. **Reproducible + independently verified** — second full run on vitalik.eth
   (test-audit-vitalik-eth-v2.json, 2026-10-14T04:04:51Z): identical
   703/202/66/15 stats; 202/202 revoke calldata decode pass; 5/5 largest
   approvals re-verified via a separate RPC provider.
4. **x402 handshake is real** — `test-audit-402-no-payment.json` and
   `test-audit-402-v2.json` (402 + accepts on /audit), malformed-payment 402
   fail-closed, Vercel handler unit-tested (200/400/405/402 paths).
5. v1 contract-scan evidence preserved in TEST-EVIDENCE.md.

## What is NOT done (blockers, stated plainly)

1. **No public deployment.** Vercel-ready but not deployed — needs a Vercel
   account/project (or any host): `cd vercel && vercel --prod`, then set
   `PUBLIC_BASE_URL` / `X402_RESOURCE_URL` to the live domain. The sandbox has
   no inbound path (four tunnel types tried and blocked). `DEPLOY.md` has the
   runbook.
2. **No Etherscan key configured** (optional): without one, Base log discovery
   depends on Blockscout reachability from the deploy network. A free
   Etherscan API key as `ETHERSCAN_API_KEY` unlocks full multi-chain discovery.

## File map

| File | What it is |
|---|---|
| `server.js` | The endpoint (zero-dep Node): `POST /audit` (approval audit) + `POST /check` (contract scan). `PORT`, `PUBLIC_BASE_URL`, `X402_RESOURCE_URL`, `PAYMENT_ADDRESS`, `PRICE_USDCENTS`, `X402_FACILITATOR_URL`, `ETHERSCAN_API_KEY` env-configurable |
| `vercel/` | Deploy-ready serverless package: `api/audit.js`, `api/health.js`, `api/_lib/{approvals,x402}.js`, `public/.well-known/x402.json`, `vercel.json` |
| `vercel/api/_lib/approvals.js` | Approval enumeration module (shared by server.js and Vercel) |
| `start-public.sh` | One-command local start (payment-gated) |
| `BOUNTY-STATUS.md` | Open/closed evidence, exact board requirements, deadline, submission format |
| `TEST-EVIDENCE.md` | Test record: requests, responses, wallets, timestamps |
| `SUBMISSION.md` | Board-format submission draft (what would go in `submissions/` + PR body). **Not filed.** |
| `DEPLOY.md` | Public deploy runbook (Vercel + any-machine) |
| `test-audit-vitalik-eth.json` | Full audit response — vitalik.eth, Ethereum, 202 live approvals |
| `test-audit-vitalik-eth-v2.json` | Independent re-run — vitalik.eth, Ethereum, identical 703/202/66/15 (2026-10-14T04:04:51Z) |
| `test-audit-foil-base-eth.json` | Foil wallet, Base (degraded) + Ethereum — honest coverage notes |
| `test-audit-402-no-payment.json` / `test-audit-402-v2.json` | 402 + x402 accepts payload on /audit (no payment header) |
| `test1-usdc-base.json` / `test2-weth-eth.json` | v1 contract-scan responses (preserved) |
| `test-402-no-payment.json` / `test-402-bad-payment.json` | v1 x402 402 evidence (preserved) |
| `tunnel.log`, `smee.log` | Dead-end tunnel attempts (for the record) |

## To submit (user action only)

1. Review this package. 2. Confirm the Solana payout address in SUBMISSION.md.
3. Say the word — a PR is then opened against `daydreamsai/agent-bounties`
   linking issue #5, with `SUBMISSION.md` as the submission file. Nothing moves
   before that.
