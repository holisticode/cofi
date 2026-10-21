# CoFi Devnet

Two-process setup: CometBFT (consensus + P2P + RPC) + cofi-node (ABCI state machine).

## Prerequisites

- Rust toolchain (already installed)
- [CometBFT](https://github.com/cometbft/cometbft) ≥ v0.38 (ABCI 2.0)

```bash
# Install CometBFT (Linux). v0.38.12 is the last release with prebuilt
# linux binaries; newer releases are source-only.
wget https://github.com/cometbft/cometbft/releases/download/v0.38.12/cometbft_0.38.12_linux_amd64.tar.gz
tar xzf cometbft_0.38.12_linux_amd64.tar.gz
mv cometbft ~/.local/bin/   # or /usr/local/bin/
```

## Quick Start

```bash
# 1. Initialize CometBFT (generates the node's consensus key)
cometbft init --home ./cometbft-data

# 2. Extract the node's validator public key as hex (64 hex chars).
#    The genesis app_state MUST use this key — it's what the node signs with.
cometbft show-validator --home ./cometbft-data \
  | python3 -c "import json,sys,base64; print(base64.b64decode(json.load(sys.stdin)['value']).hex())"

# 3. Put that hex into cometbft-data/config/genesis.json app_state
#    (see "Genesis app_state" below).

# 4. Build and start cofi-node (ABCI server)
cargo build -p cofi-node
./target/debug/cofi-node --data-dir ./cofi-data

# 5. Start CometBFT (in another terminal, after cofi-node is ready)
#    No --proxy-app flag: proxy_app is configured in config.toml.
cometbft start --home ./cometbft-data
```

## Configuration

### CometBFT config.toml

The default `proxy_app` already matches the cofi-node ABCI bind address;
cofi-node also binds `127.0.0.1:26658` by default:

```toml
proxy_app = "tcp://127.0.0.1:26658"
```

### Genesis app_state

Edit `cometbft-data/config/genesis.json` and add `app_state`:

```json
{
  "app_state": {
    "asset_types": [
      { "id": "code", "name": "Code contribution", "weight": 10 },
      { "id": "infrastructure", "name": "Infrastructure service", "weight": 10 }
    ],
    "validators": [
      {
        "contributor_id": "validator-1",
        "public_key_hex": "<hex from step 2 above>"
      }
    ],
    "charter": {
      "numerator": 2,
      "denominator": 3
    }
  }
}
```

The validator's key must be the node's own consensus key
(`cometbft-data/config/priv_validator_key.json`), otherwise the node cannot
sign for its validator slot and consensus stalls.

## Using the client

`cofi-client` builds, signs, and submits txs via CometBFT's RPC:

```bash
cargo build -p cofi-client

# Generate a keypair for a contributor
./target/debug/cofi-client keygen --key alice.key

# Submit a contribution (enters the review pool)
./target/debug/cofi-client contribution --contributor alice --asset-type code --amount 10

# The genesis validator reviews it (commit-reveal, two phases).
# A validator key file is a 32- or 64-byte hex seed. Export the node's key:
python3 -c "
import json, base64
pv = json.load(open('cometbft-data/config/priv_validator_key.json'))
print(base64.b64decode(pv['priv_key']['value']).hex())
" > validator.key

./target/debug/cofi-client commit-vote --pending-id 1 --key validator.key
./target/debug/cofi-client reveal-vote --pending-id 1 --key validator.key

# Query state
./target/debug/cofi-client query balance/alice
./target/debug/cofi-client query state
./target/debug/cofi-client query pool

# Register alice's key once she has units — she becomes a validator
./target/debug/cofi-client register-key --contributor alice --key alice.key

# Redeem units (self-signed exit message)
./target/debug/cofi-client redeem --contributor alice --amount 30 --key alice.key
```

## Transaction Format

Transactions are JSON with a `type` tag, submitted via CometBFT's
`broadcast_tx_*` RPC as base64. `cofi-client` builds them from the exact
`CoFiTx` types (cofi-node/src/tx.rs), so use the client rather than hand-crafting.

Transaction types (`CoFiTx`):
- `{"type":"contribution","contributor":"alice","asset_type":"code","amount":10}`
- `{"type":"redemption","contributor":"alice","amount":30,"signature":[64 bytes]}`
- `{"type":"register_key","contributor_id":"alice","public_key":[32 bytes]}`
- `{"type":"commit_vote","pending_id":1,"commitment":{"reviewer":[32 bytes],"commitment":[32 bytes],"signature":[64 bytes]}}`
- `{"type":"reveal_vote","pending_id":1,"reveal":{"reviewer":[32 bytes],"approve":true,"salt":[32 bytes]}}`

Ed25519 keys and signatures serialize as JSON byte arrays, not base64.

## ABCI Query Endpoints

CometBFT proxies these to our ABCI app at `/abci_query?path=...`:

| Path | Description |
|---|---|
| `state` | Full CoFiState JSON |
| `balance/<contributor>` | Units for a contributor |
| `pool` | ReviewPool status |
