use cofi_contracts::{
    Contribution, ContributorId, CoFiState,
    store::{SledStore, StateStore},
    validation::ReviewPool,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tendermint_proto::v0_38::abci::{
    ExecTxResult, RequestCheckTx, RequestFinalizeBlock, RequestInfo, RequestInitChain,
    RequestQuery, ResponseCheckTx, ResponseCommit, ResponseFinalizeBlock, ResponseInfo,
    ResponseInitChain, ResponseQuery, ValidatorUpdate,
};
use tendermint_proto::v0_38::crypto::public_key::Sum as PkSum;
use tracing::{debug, info};

use crate::tx::{CoFiTx, decode_tx};

/// BlockIdFlag value for "voted for the block" (BLOCK_ID_FLAG_COMMIT = 2).
const BLOCK_ID_FLAG_COMMIT: i32 = 2;

// ---------------------------------------------------------------------------
// App state
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AppState {
    cofi: CoFiState,
    pool: ReviewPool,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            cofi: CoFiState::new(),
            pool: ReviewPool::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// ABCI application
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct CoFiApp {
    state: Arc<Mutex<AppState>>,
    store: Arc<SledStore>,
    height: Arc<Mutex<u64>>,
}

impl CoFiApp {
    pub fn new(store: SledStore) -> Self {
        let state = load_or_init(&store);
        Self {
            state: Arc::new(Mutex::new(state)),
            store: Arc::new(store),
            height: Arc::new(Mutex::new(0)),
        }
    }

    pub fn run(addr: &str, store: SledStore) -> Result<(), Box<dyn std::error::Error>> {
        let app = Self::new(store);
        let server = tendermint_abci::ServerBuilder::default().bind(addr, app)?;
        info!("ABCI server listening on {}", server.local_addr());
        server.listen()?;
        Ok(())
    }
}

impl tendermint_abci::Application for CoFiApp {
    fn info(&self, _request: RequestInfo) -> ResponseInfo {
        let s = self.state.lock().unwrap();
        let h = *self.height.lock().unwrap();
        let root = s.cofi.state_root();
        ResponseInfo {
            data: "cofi-node".into(),
            version: "0.1.0".into(),
            app_version: 1,
            last_block_height: h as i64,
            last_block_app_hash: root.to_vec().into(),
        }
    }

    fn init_chain(&self, request: RequestInitChain) -> ResponseInitChain {
        let mut s = self.state.lock().unwrap();
        let genesis: GenesisState =
            serde_json::from_slice(&request.app_state_bytes).unwrap_or_default();

        for at in genesis.asset_types {
            let _ = s.cofi.register_asset_type(at);
        }

        if let Some(ch) = genesis.charter {
            s.cofi.quorum_config = ch;
        }

        for ct in genesis.contributor_types {
            let _ = s.cofi.register_contributor_type(ct);
        }

        let mut validators = Vec::new();
        for gv in genesis.validators {
            let id = gv.contributor_id.clone();
            let pk = match gv.public_key() {
                Ok(pk) => pk,
                Err(e) => {
                    tracing::warn!("Skipping genesis validator {}: {e}", id);
                    continue;
                }
            };
            s.cofi.contributor_units.entry(id.clone()).or_insert(1);
            s.cofi.total_contribution_units += 1;
            s.cofi
                .contributor_keys
                .insert(id.clone(), pk);
            validators.push(ValidatorUpdate {
                pub_key: Some(tendermint_proto::v0_38::crypto::PublicKey {
                    sum: Some(PkSum::Ed25519(pk.to_bytes().to_vec())),
                }),
                power: 1,
            });
        }

        let app_hash = s.cofi.state_root().to_vec().into();
        ResponseInitChain {
            consensus_params: None,
            validators,
            app_hash,
        }
    }

    fn query(&self, request: RequestQuery) -> ResponseQuery {
        let s = self.state.lock().unwrap();
        let path = request.path.as_str();

        let (code, value) = match path {
            "state" => {
                let json = serde_json::to_vec(&*s).unwrap();
                (0, json)
            }
            _ if path.starts_with("balance/") => {
                let id = &path["balance/".len()..];
                let units = s.cofi.contributor_units.get(id).copied().unwrap_or(0);
                let json = serde_json::json!({ "contributor": id, "units": units });
                (0, serde_json::to_vec(&json).unwrap())
            }
            "pool" => {
                let json = serde_json::to_vec(&s.pool).unwrap();
                (0, json)
            }
            _ => {
                (1, format!("unknown query path: {path}").into_bytes())
            }
        };

        ResponseQuery {
            code,
            log: "".into(),
            info: "".into(),
            index: 0,
            key: request.data,
            value: value.into(),
            proof_ops: None,
            height: *self.height.lock().unwrap() as i64,
            codespace: "".into(),
        }
    }

    fn check_tx(&self, request: RequestCheckTx) -> ResponseCheckTx {
        let code = if decode_tx(&request.tx).is_ok() { 0 } else { 1 };
        ResponseCheckTx {
            code,
            data: Default::default(),
            log: "".into(),
            info: "".into(),
            gas_wanted: 1,
            gas_used: 0,
            events: vec![],
            codespace: "".into(),
        }
    }

    fn finalize_block(&self, request: RequestFinalizeBlock) -> ResponseFinalizeBlock {
        let mut s = self.state.lock().unwrap();
        *self.height.lock().unwrap() = request.height as u64;

        // Phase 1: Credit infrastructure contributions to validators who
        // signed the previous block (decided_last_commit).
        if let Some(ref last_commit) = request.decided_last_commit {
            let addr_map = build_address_map(&s.cofi);
            for vote in &last_commit.votes {
                if vote.block_id_flag != BLOCK_ID_FLAG_COMMIT {
                    continue;
                }
                if let Some(ref validator) = vote.validator {
                    if let Some(contrib_id) = addr_map.get(validator.address.as_ref()) {
                        let contrib = Contribution {
                            contributor: contrib_id.clone(),
                            asset_type: "infrastructure".into(),
                            amount: 1,
                        };
                        let _ = s.cofi.process_contribution(contrib);
                    }
                }
            }
        }

        // Phase 2: Process each transaction.
        let mut tx_results = Vec::with_capacity(request.txs.len());
        for tx_bytes in &request.txs {
            tx_results.push(execute_tx(&mut s, tx_bytes));
        }

        // Phase 3: Auto-approve, drain approved, apply to state.
        let (reviewers, units) = {
            let cofi = &s.cofi;
            (cofi.derive_reviewers(), cofi.contributor_units.clone())
        };
        s.pool.auto_approve_if_no_reviewers(&reviewers, &units);
        let approved = s.pool.drain_approved();
        for c in approved {
            let _ = s.cofi.process_contribution(c);
        }

        // Phase 4: Build validator set updates.
        let validator_updates = build_validator_updates(&s.cofi);

        // Phase 5: Compute app hash.
        let app_hash = s.cofi.state_root().to_vec().into();

        ResponseFinalizeBlock {
            events: vec![],
            tx_results,
            validator_updates,
            consensus_param_updates: None,
            app_hash,
        }
    }

    fn commit(&self) -> ResponseCommit {
        let s = self.state.lock().unwrap();
        let root = s.cofi.state_root();

        let value = serde_json::to_vec(&*s).expect("AppState serialization is infallible");
        self.store.put(b"latest", &value).expect("store write failed");
        self.store.commit_root(&root).expect("store commit failed");

        let h = *self.height.lock().unwrap();
        debug!("Committed height {h}, app_hash={}", hex::encode(root));

        ResponseCommit {
            retain_height: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// Tx execution
// ---------------------------------------------------------------------------

fn execute_tx(s: &mut AppState, tx_bytes: &[u8]) -> ExecTxResult {
    let tx = match decode_tx(tx_bytes) {
        Ok(tx) => tx,
        Err(e) => {
            return ExecTxResult {
                code: 1,
                data: Default::default(),
                log: format!("decode: {e}"),
                info: "".into(),
                gas_wanted: 1,
                gas_used: 0,
                events: vec![],
                codespace: "".into(),
            };
        }
    };

    match tx {
        CoFiTx::Contribution(contrib) => {
            s.pool.submit(contrib);
            ok_result()
        }
        CoFiTx::Redemption(redemption) => match s.cofi.process_redemption(redemption) {
            Ok(_) => ok_result(),
            Err(e) => err_result(&format!("{e:?}")),
        },
        CoFiTx::RegisterKey {
            contributor_id,
            public_key,
        } => match s.cofi.register_contributor_key(contributor_id, public_key) {
            Ok(_) => ok_result(),
            Err(e) => err_result(&format!("{e:?}")),
        },
        CoFiTx::CommitVote {
            pending_id,
            commitment,
        } => {
            let (reviewers, units) = {
                let cofi = &s.cofi;
                (cofi.derive_reviewers(), cofi.contributor_units.clone())
            };
            match s.pool.commit_vote(pending_id, commitment, &reviewers, &units) {
                Ok(_) => ok_result(),
                Err(e) => err_result(&format!("{e:?}")),
            }
        }
        CoFiTx::RevealVote {
            pending_id,
            reveal,
        } => {
            let (reviewers, quorum) = {
                let cofi = &s.cofi;
                (cofi.derive_reviewers(), cofi.quorum_config.clone())
            };
            match s.pool.reveal_vote(pending_id, reveal, &quorum, &reviewers) {
                Ok(_) => ok_result(),
                Err(e) => err_result(&format!("{e:?}")),
            }
        }
    }
}

fn ok_result() -> ExecTxResult {
    ExecTxResult {
        code: 0,
        data: Default::default(),
        log: "".into(),
        info: "".into(),
        gas_wanted: 1,
        gas_used: 0,
        events: vec![],
        codespace: "".into(),
    }
}

fn err_result(msg: &str) -> ExecTxResult {
    ExecTxResult {
        code: 2,
        data: Default::default(),
        log: msg.to_string(),
        info: "".into(),
        gas_wanted: 1,
        gas_used: 0,
        events: vec![],
        codespace: "".into(),
    }
}

// ---------------------------------------------------------------------------
// Genesis state
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct GenesisState {
    #[serde(default)]
    asset_types: Vec<cofi_contracts::AssetType>,
    #[serde(default)]
    contributor_types: Vec<cofi_contracts::governance::ContributorType>,
    #[serde(default)]
    validators: Vec<GenesisValidator>,
    #[serde(default)]
    charter: Option<cofi_contracts::validation::QuorumConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct GenesisValidator {
    contributor_id: ContributorId,
    /// Ed25519 public key as a hex-encoded string (64 hex chars).
    public_key_hex: String,
}

impl GenesisValidator {
    fn public_key(&self) -> Result<ed25519_dalek::VerifyingKey, String> {
        let bytes = hex::decode(&self.public_key_hex)
            .map_err(|e| format!("invalid hex public key: {e}"))?;
        if bytes.len() != 32 {
            return Err(format!("public key must be 32 bytes, got {}", bytes.len()));
        }
        let arr: [u8; 32] = bytes.try_into().unwrap();
        ed25519_dalek::VerifyingKey::from_bytes(&arr)
            .map_err(|e| format!("invalid ed25519 key: {e}"))
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn validator_address(pk: &ed25519_dalek::VerifyingKey) -> Vec<u8> {
    Sha256::digest(pk.as_bytes())[..20].to_vec()
}

fn build_address_map(state: &CoFiState) -> HashMap<Vec<u8>, ContributorId> {
    let mut map = HashMap::new();
    for (id, key) in &state.contributor_keys {
        map.insert(validator_address(key), id.clone());
    }
    map
}

fn build_validator_updates(state: &CoFiState) -> Vec<ValidatorUpdate> {
    let mut updates = Vec::new();
    for (id, &units) in &state.contributor_units {
        if units == 0 {
            continue;
        }
        if let Some(key) = state.contributor_keys.get(id) {
            updates.push(ValidatorUpdate {
                pub_key: Some(tendermint_proto::v0_38::crypto::PublicKey {
                    sum: Some(PkSum::Ed25519(key.to_bytes().to_vec())),
                }),
                power: units as i64,
            });
        }
    }
    updates
}

// ---------------------------------------------------------------------------
// Persistence
// ---------------------------------------------------------------------------

fn load_or_init(store: &SledStore) -> AppState {
    if let Ok(Some(value)) = store.get(b"latest") {
        if let Ok(state) = serde_json::from_slice(&value) {
            return state;
        }
    }
    AppState::default()
}
