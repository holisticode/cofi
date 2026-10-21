# CoFi — Proof of Contribution

**Community wealth, cooperatively managed.** A blockchain where contributions — work, not coins — become governance power.

CoFi is a learning project: an exploration of contribution-weighted governance, built end-to-end from the state machine to a live devnet. No proof-of-stake, no proof-of-work. Validator voting power equals reviewed contribution units.

## The idea

Most blockchains give power to those who already hold coins. CoFi gives power to those who build the community — and proves it.

| DAOs (typically) | CoFi |
|---|---|
| Governance power = tokens held | Governance power = contributions made |
| Capital has automatic dominance | Capital is one contribution type among many |
| You buy in | You contribute in |
| Capital-weighted | **Contribution-weighted** |

- **One shared pool.** Every contribution — code, design, community, support, funding, infrastructure — lands in a single pool of contribution units. Your share of the pool is your share of governance.
- **Work becomes power.** Units are minted by peer-reviewed work, not bought with coins. Validator voting power equals contribution units.
- **Measure, don't trust.** Only what can be proven counts: signed blocks, reviewed work, pro-rata timing. Never self-reports.

## Two-layer contribution model

| Layer | What | Verified by | Earns |
|---|---|---|---|
| 1 — Infrastructure (consensus) | Running nodes, signing blocks | Cryptographically, via CometBFT `LastCommitInfo` | `infrastructure` units per signed block |
| 2 — Project (governance) | Code, hardware, design, community, funding | Peer review (commit-reveal) | Asset-type units, pro-rata against the pool |

Both layers earn into the same pool.

## How it works

1. **Contribute** — record real work as a weighted asset type. `amount × weight` = asset units.
2. **Review** — contributors with skin in the game vote commit-reveal style. Quorum (default ⅔) approves; self-approval is blocked. Until the first reviewers exist, bootstrap approval starts the pool.
3. **Mint** — `units = asset_units × total_contrib ÷ total_asset`. The pool's current size prices each unit of work, so early contributions mint more units per unit of work.
4. **Claim** — the pool grows only by minting units to new reviewed work. Your units are never debited or diluted: at any moment, your claim is exactly what you earned.
5. **Redeem** — leaving is a signed message, not a negotiation. Redeem part or all of your units and exit with what you've earned.

## Architecture

CometBFT (Go) handles consensus, P2P, mempool, and JSON-RPC. cofi-node (Rust) is an ABCI 2.0 application. Separation of concerns: CometBFT doesn't know what "voting power" means — the app just returns validator set updates where `power = contribution_units`.

```
contributors ── txs ──▶ cofi-node (ABCI 2.0 app) ◀── blocks ── CometBFT (consensus)
                        │  state machine · review pool · redemption
                        └── validator set updates: power = contribution_units
```

## Crates

| Crate | Purpose |
|---|---|
| [`cofi-contracts`](cofi-contracts/) | State machine, store, Merkle root, contribution review (commit-reveal), governance, charter |
| [`cofi-block`](cofi-block/) | Standalone block/chain implementation (for testing) |
| [`cofi-node`](cofi-node/) | ABCI 2.0 application for CometBFT (production node) |
| [`cofi-client`](cofi-client/) | CLI client: `keygen`, `contribution`, `commit-vote`, `reveal-vote`, `register-key`, `redeem`, `query` |

## Status

The full protocol loop is verified end-to-end on a live devnet (2026-10-20): contribution → commit-reveal review → approval → validator set update → redemption, with infrastructure rewards accruing per block. 93 tests across the workspace.

Open work: multi-validator devnet, cofi-node integration tests, SDK growth.

**CoFi is a learning project — not production-ready, no mainnet.**

## Run the devnet

Full setup guide: [`cofi-node/devnet/README.md`](cofi-node/devnet/README.md). Quick start:

```bash
cargo build
cd cofi-node/devnet
../../target/debug/cofi-node --data-dir ./cofi-data   # terminal 1
~/.local/bin/cometbft start --home ./cometbft-data    # terminal 2
```

Requires CometBFT 0.38.x. Note: CometBFT releases after 0.38.12 ship no prebuilt binaries.

## Tests

```bash
cargo test
```

## Website

A landing page explaining CoFi, plus a live demo animation of the protocol loop, live in [`cofi-web/`](cofi-web/). Open `cofi-web/index.html` in a browser — static hosting to be decided.

## Further reading

| File | Purpose |
|---|---|
| [`CONCEPT.md`](CONCEPT.md) | CoFi protocol design |
