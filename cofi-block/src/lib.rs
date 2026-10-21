use cofi_contracts::{
    CoFiState, Contribution, ContributionResult, Redemption, RedemptionResult, StateKey,
    key_prefix,
    store::{LoadError, StateStore, load_state},
    validation::ReviewPool,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// Block header
// ---------------------------------------------------------------------------

/// Compact block metadata — small enough for light clients to sync and verify
/// the chain without downloading contribution payloads.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockHeader {
    /// Monotonically increasing position in the chain.
    pub height: u64,
    /// Hash of the previous block's header. Zero-filled for the genesis block.
    pub parent_hash: [u8; 32],
    /// Merkle root of CoFiState after applying this block's contributions.
    pub state_root: [u8; 32],
    /// Hash of the serialized contribution list — proves body integrity
    /// without requiring the full payload.
    pub body_hash: [u8; 32],
    /// Unix timestamp in seconds, set at block creation.
    pub timestamp: u64,
}

impl BlockHeader {
    pub fn hash(&self) -> [u8; 32] {
        let json = serde_json::to_vec(self).expect("BlockHeader serialization is infallible");
        let mut h = [0u8; 32];
        h.copy_from_slice(&Sha256::digest(&json));
        h
    }
}

// ---------------------------------------------------------------------------
// Block
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Block {
    pub header: BlockHeader,
    pub contributions: Vec<Contribution>,
    pub redemptions: Vec<Redemption>,
}

impl Block {
    /// Convenience: delegates to `header.hash()`.
    pub fn hash(&self) -> [u8; 32] {
        self.header.hash()
    }
}

// ---------------------------------------------------------------------------
// BlockResult
// ---------------------------------------------------------------------------

/// Result of block production — the block plus per-item outcomes.
#[derive(Debug)]
pub struct BlockResult {
    /// The produced block. Only successfully applied items are included.
    pub block: Block,
    /// Per-contribution outcome, in submission order.
    pub contribution_results: Vec<Result<ContributionResult, cofi_contracts::Error>>,
    /// Per-redemption outcome, in submission order.
    pub redemption_results: Vec<Result<RedemptionResult, cofi_contracts::Error>>,
}

// ---------------------------------------------------------------------------
// Chain
// ---------------------------------------------------------------------------

/// A CoFi blockchain — owns the application state and enforces hash chain
/// continuity across blocks.
///
/// `Chain` wraps [`CoFiState`] with the minimal chain metadata needed to
/// produce valid blocks: current height and the previous block's hash.
/// The caller cannot accidentally pass the wrong height or parent hash
/// because the chain manages both automatically.
#[derive(Debug)]
pub struct Chain {
    /// Application state (asset types, contributor balances, totals).
    pub state: CoFiState,
    /// Height of the most recently produced block. Starts at 0 (genesis).
    pub height: u64,
    /// Hash of the most recently produced block. Zero-filled at genesis.
    pub last_block_hash: [u8; 32],
}

impl Chain {
    /// Create a new chain at genesis: height 0, empty state, zero parent hash.
    pub fn genesis() -> Self {
        Self {
            state: CoFiState::new(),
            height: 0,
            last_block_hash: [0u8; 32],
        }
    }

    /// Apply contributions and redemptions, then produce the next block.
    ///
    /// Contributions are applied first, then redemptions — though in practice
    /// redemptions draw from units earned in prior blocks, so the ordering
    /// within a single block is irrelevant for correctness.
    ///
    /// Items that fail validation are **skipped** — they do not appear in the
    /// block and do not affect the state root. Their errors are collected in
    /// [`BlockResult::contribution_results`] and
    /// [`BlockResult::redemption_results`].
    ///
    /// After this call, `self.height` and `self.last_block_hash` are updated
    /// to reflect the newly produced block.
    pub fn produce_block(
        &mut self,
        contributions: Vec<Contribution>,
        redemptions: Vec<Redemption>,
        timestamp: u64,
    ) -> BlockResult {
        let mut accepted_contribs: Vec<Contribution> = Vec::new();
        let mut contrib_results: Vec<Result<ContributionResult, cofi_contracts::Error>> =
            Vec::new();

        for c in &contributions {
            match self.state.process_contribution(c.clone()) {
                Ok(cr) => {
                    accepted_contribs.push(c.clone());
                    contrib_results.push(Ok(cr));
                }
                Err(e) => contrib_results.push(Err(e)),
            }
        }

        let mut accepted_redemptions: Vec<Redemption> = Vec::new();
        let mut redemption_results: Vec<Result<RedemptionResult, cofi_contracts::Error>> =
            Vec::new();

        for r in &redemptions {
            match self.state.process_redemption(r.clone()) {
                Ok(rr) => {
                    accepted_redemptions.push(r.clone());
                    redemption_results.push(Ok(rr));
                }
                Err(e) => redemption_results.push(Err(e)),
            }
        }

        let next_height = self.height + 1;
        let parent_hash = self.last_block_hash;
        let state_root = self.state.state_root();
        let body_hash = compute_body_hash(&accepted_contribs, &accepted_redemptions);

        let block = Block {
            header: BlockHeader {
                height: next_height,
                parent_hash,
                state_root,
                body_hash,
                timestamp,
            },
            contributions: accepted_contribs,
            redemptions: accepted_redemptions,
        };

        self.height = next_height;
        self.last_block_hash = block.hash();

        BlockResult {
            block,
            contribution_results: contrib_results,
            redemption_results,
        }
    }

    /// Produce a block from the review pool: drains approved contributions,
    /// applies redemptions, then delegates to [`produce_block`].
    pub fn produce_from_pool(
        &mut self,
        pool: &mut ReviewPool,
        redemptions: Vec<Redemption>,
        timestamp: u64,
    ) -> BlockResult {
        self.produce_block(pool.drain_approved(), redemptions, timestamp)
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Compute the body hash for a block's payload.
pub fn compute_body_hash(contributions: &[Contribution], redemptions: &[Redemption]) -> [u8; 32] {
    let json =
        serde_json::to_vec(&(contributions, redemptions)).expect("serialization is infallible");
    let mut h = [0u8; 32];
    h.copy_from_slice(&Sha256::digest(&json));
    h
}

/// Genesis block — height 0, no parent, empty body.
pub fn genesis_block() -> Block {
    Block {
        header: BlockHeader {
            height: 0,
            parent_hash: [0u8; 32],
            state_root: [0u8; 32],
            body_hash: compute_body_hash(&[], &[]),
            timestamp: 0,
        },
        contributions: vec![],
        redemptions: vec![],
    }
}

pub fn flush_block<S: StateStore>(
    store: &S,
    block: &Block,
    state: &CoFiState,
) -> Result<(), S::Error> {
    // 1. Asset types — use state.asset_types, not the block
    for (id, at) in &state.asset_types {
        let value = serde_json::to_vec(at).expect("AssetType serialization is infallible");
        store.put(&StateKey::AssetType(id.clone()).encode(), &value)?;
    }

    // 2. Contributor types
    for (id, ct) in &state.contributor_types {
        let value = serde_json::to_vec(ct).expect("ContributorType serialization is infallible");
        store.put(&StateKey::ContributorType(id.clone()).encode(), &value)?;
    }

    // 3. Contributor units
    for (id, &units) in &state.contributor_units {
        store.put(
            &StateKey::ContributorUnits(id.clone()).encode(),
            &units.to_le_bytes(),
        )?;
    }

    // 4. Contributor keys
    for (id, key) in &state.contributor_keys {
        let value =
            serde_json::to_vec(key).expect("VerifyingKey serialization is infallible");
        store.put(&StateKey::ContributorKey(id.clone()).encode(), &value)?;
    }

    // 5. Quorum config
    let quorum_value =
        serde_json::to_vec(&state.quorum_config).expect("QuorumConfig serialization is infallible");
    store.put(&StateKey::QuorumConfig.encode(), &quorum_value)?;

    // 6. Totals
    store.put(
        &StateKey::TotalAsset.encode(),
        &state.total_asset_units.to_le_bytes(),
    )?;
    store.put(
        &StateKey::TotalContrib.encode(),
        &state.total_contribution_units.to_le_bytes(),
    )?;

    // 7. The block itself
    let block_json = serde_json::to_vec(block).expect("Block serialization is infallible");
    store.put(&block_key(block.header.height), &block_json)?;

    // 8. Commit the Merkle root
    store.commit_root(&state.state_root())?;

    Ok(())
}

fn block_key(height: u64) -> Vec<u8> {
    let mut block_key: Vec<u8> = vec![key_prefix::BLOCK_STORAGE];
    block_key.extend_from_slice(&height.to_le_bytes());

    block_key
}

pub fn load_chain<S: StateStore>(store: &S) -> Result<Chain, LoadError<S>> {
    let state = load_state(store)?;
    let key_list = store
        .scan_prefix([key_prefix::BLOCK_STORAGE].as_slice())
        .map_err(LoadError::Store)?;

    let mut best: Option<Block> = None;
    for (_, value) in key_list {
        let block: Block =
            serde_json::from_slice(&value).map_err(|e| LoadError::Corrupt(e.to_string()))?;
        match &best {
            Some(current) if block.header.height <= current.header.height => {}
            _ => best = Some(block),
        }
    }
    let (height, last_block_hash) = match best {
        Some(block) => (block.header.height, block.hash()),
        None => (0, [0u8; 32]),
    };

    Ok(Chain {
        state,
        height,
        last_block_hash,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use cofi_contracts::{AssetId, AssetType, Contribution, ContributorId, Redemption, store::SledStore};
    use ed25519_dalek::Signer;
    use ed25519_dalek::SigningKey;

    fn temp_store() -> SledStore {
        // add this helper
        let dir = tempfile::tempdir().unwrap();
        SledStore::open(dir.path()).unwrap()
    }

    fn make_contributions(n: u32) -> Vec<Contribution> {
        (1..=n)
            .map(|i| Contribution {
                contributor: ContributorId::from(format!("user{}", i)),
                asset_type: AssetId::from("code"),
                amount: i as u64 * 100,
            })
            .collect()
    }

    #[test]
    fn block_hash_is_deterministic() {
        let block = genesis_block();
        assert_eq!(block.hash(), block.hash());
    }

    #[test]
    fn different_contributions_produce_different_body_hash() {
        let a: Vec<Contribution> = vec![];
        let b = vec![Contribution {
            contributor: "alice".into(),
            asset_type: "code".into(),
            amount: 1,
        }];
        let empty: Vec<Redemption> = vec![];
        assert_ne!(
            compute_body_hash(&a, &empty),
            compute_body_hash(&b, &empty)
        );
    }

    #[test]
    fn parent_hash_links_blocks() {
        let parent = genesis_block();
        let child = Block {
            header: BlockHeader {
                height: 1,
                parent_hash: parent.hash(),
                state_root: [0u8; 32],
                body_hash: compute_body_hash(&[], &[]),
                timestamp: 1,
            },
            contributions: vec![],
            redemptions: vec![],
        };

        assert_eq!(child.header.parent_hash, parent.hash());
        assert_ne!(parent.hash(), child.hash());
    }

    #[test]
    fn produce_block_with_valid_contributions() {
        let mut chain = Chain::genesis();

        chain
            .state
            .register_asset_type(AssetType {
                id: AssetId::from("code"),
                name: String::from("code"),
                weight: 10,
            })
            .unwrap();

        let c1 = Contribution {
            contributor: ContributorId::from("alice"),
            asset_type: AssetId::from("code"),
            amount: 10,
        };
        let c2 = Contribution {
            contributor: ContributorId::from("bob"),
            asset_type: AssetId::from("code"),
            amount: 20,
        };
        let contributions = vec![c1, c2];
        let block_result = chain.produce_block(contributions, vec![], 100);

        assert_eq!(block_result.block.header.height, 1);
        assert_eq!(block_result.block.header.parent_hash, [0u8; 32]);
        assert_ne!(block_result.block.header.state_root, [0u8; 32]);
        assert_eq!(
            block_result.block.header.body_hash,
            compute_body_hash(&block_result.block.contributions, &block_result.block.redemptions)
        );
        assert_eq!(chain.state.total_asset_units, 300);
        assert_eq!(chain.state.total_contribution_units, 300);
        assert_eq!(chain.height, 1);
    }

    #[test]
    fn filters_invalid_contributions() {
        let mut chain = Chain::genesis();

        let c1 = Contribution {
            contributor: ContributorId::from("alice"),
            asset_type: AssetId::from("unknown"),
            amount: 10,
        };
        let c2 = Contribution {
            contributor: ContributorId::from("alice"),
            asset_type: AssetId::from("unknown"),
            amount: 0,
        };
        let contributions = vec![c1, c2];
        let block_result = chain.produce_block(contributions, vec![], 100);

        assert_eq!(block_result.block.contributions.len(), 0);
        for e in block_result.contribution_results {
            assert!(e.is_err());
        }
        assert_eq!(chain.state.total_asset_units, 0);
        assert_eq!(chain.state.total_contribution_units, 0);
    }

    #[test]
    fn consecutive_blocks_link() {
        let mut chain = Chain::genesis();

        chain
            .state
            .register_asset_type(AssetType {
                id: AssetId::from("code"),
                name: String::from("code"),
                weight: 10,
            })
            .unwrap();

        let c1 = Contribution {
            contributor: ContributorId::from("alice"),
            asset_type: AssetId::from("code"),
            amount: 10,
        };
        let c2 = Contribution {
            contributor: ContributorId::from("bob"),
            asset_type: AssetId::from("code"),
            amount: 20,
        };

        let block_result1 = chain.produce_block(vec![c1], vec![], 100);
        assert_eq!(block_result1.block.header.height, 1);

        let block_result2 = chain.produce_block(vec![c2], vec![], 100);
        assert_eq!(block_result2.block.header.height, 2);
        assert_eq!(
            block_result2.block.header.parent_hash,
            block_result1.block.hash()
        );
        assert_ne!(
            block_result1.block.header.state_root,
            block_result2.block.header.state_root
        );
    }

    #[test]
    fn mixed_valid_and_invalid() {
        let mut chain = Chain::genesis();

        chain
            .state
            .register_asset_type(AssetType {
                id: AssetId::from("valid"),
                name: String::from("valid"),
                weight: 10,
            })
            .unwrap();

        let c1 = Contribution {
            contributor: ContributorId::from("alice"),
            asset_type: AssetId::from("valid"),
            amount: 10,
        };
        let c2 = Contribution {
            contributor: ContributorId::from("bob"),
            asset_type: AssetId::from("invalid"),
            amount: 20,
        };
        let c3 = Contribution {
            contributor: ContributorId::from("bob"),
            asset_type: AssetId::from("valid"),
            amount: 20,
        };
        let contributions = vec![c1, c2, c3];
        let block_result = chain.produce_block(contributions, vec![], 100);

        assert_eq!(block_result.block.contributions.len(), 2);

        let mut ok: u8 = 0;
        let mut err: u8 = 0;
        for e in block_result.contribution_results {
            if e.is_ok() {
                ok += 1;
            } else {
                err += 1;
            }
        }
        assert_eq!(ok, 2);
        assert_eq!(err, 1);
        assert_eq!(chain.state.total_asset_units, 300);
        assert_eq!(chain.state.total_contribution_units, 300);
    }

    #[test]
    fn chain_genesis_starts_at_zero() {
        let chain = Chain::genesis();
        assert_eq!(chain.height, 0);
        assert_eq!(chain.last_block_hash, [0u8; 32]);
        assert_eq!(chain.state.total_asset_units, 0);
    }

    #[test]
    fn rountrip() {
        let mut chain = Chain::genesis();

        chain
            .state
            .register_asset_type(AssetType {
                id: AssetId::from("one"),
                name: String::from("one"),
                weight: 10,
            })
            .unwrap();

        chain
            .state
            .register_asset_type(AssetType {
                id: AssetId::from("two"),
                name: String::from("two"),
                weight: 10,
            })
            .unwrap();

        let c1 = Contribution {
            contributor: ContributorId::from("alice"),
            asset_type: AssetId::from("one"),
            amount: 10,
        };
        let c2 = Contribution {
            contributor: ContributorId::from("bob"),
            asset_type: AssetId::from("two"),
            amount: 20,
        };
        let c3 = Contribution {
            contributor: ContributorId::from("bob"),
            asset_type: AssetId::from("two"),
            amount: 20,
        };
        let contributions = vec![c1, c2, c3];
        let block_result = chain.produce_block(contributions, vec![], 100);

        let store = &temp_store();

        assert!(flush_block(store, &block_result.block, &chain.state).is_ok());

        let control_chain = load_chain(store).unwrap();

        assert_eq!(chain.state.state_root(), control_chain.state.state_root());
        assert_eq!(
            chain.state.total_asset_units,
            control_chain.state.total_asset_units
        );
        assert_eq!(
            chain.state.total_contribution_units,
            control_chain.state.total_contribution_units
        );
        assert_eq!(chain.height, control_chain.height);
        assert_eq!(chain.last_block_hash, control_chain.last_block_hash);
    }

    #[test]
    fn load_empty_chain() {
        let store = &temp_store();
        let chain = load_chain(store).unwrap();
        assert_eq!(chain.height, 0);
        assert_eq!(chain.last_block_hash, [0u8; 32]);
        assert_eq!(chain.state.asset_types.len(), 0);
        assert_eq!(chain.state.contributor_units.len(), 0);
        assert_eq!(chain.state.contributor_types.len(), 0);
        assert_eq!(chain.state.total_contribution_units, 0);
        assert_eq!(chain.state.total_asset_units, 0);
    }
    #[test]
    fn flush_multi_block() {
        let store = &temp_store();
        let mut chain = load_chain(store).unwrap();

        chain
            .state
            .register_asset_type(AssetType {
                id: AssetId::from("code"),
                name: String::from("code"),
                weight: 10,
            })
            .unwrap();

        let b1contribs = make_contributions(3);
        let b2contribs = make_contributions(4);
        let b3contribs = make_contributions(5);
        let b1 = chain.produce_block(b1contribs, vec![], 100);
        let b2 = chain.produce_block(b2contribs, vec![], 200);
        let b3 = chain.produce_block(b3contribs, vec![], 300);

        flush_block(store, &b1.block, &chain.state).unwrap();
        flush_block(store, &b2.block, &chain.state).unwrap();
        flush_block(store, &b3.block, &chain.state).unwrap();

        let control_chain = load_chain(store).unwrap();
        assert_eq!(control_chain.height, 3);
        assert_eq!(control_chain.last_block_hash, b3.block.hash());
        assert_eq!(control_chain.state.total_contribution_units, 31000);
    }
    #[test]
    fn outoforder_flush() {
        let store = &temp_store();
        let mut chain = load_chain(store).unwrap();

        chain
            .state
            .register_asset_type(AssetType {
                id: AssetId::from("code"),
                name: String::from("code"),
                weight: 10,
            })
            .unwrap();

        let b1contribs = make_contributions(3);
        let b2contribs = make_contributions(4);
        let b3contribs = make_contributions(5);
        let b1 = chain.produce_block(b1contribs, vec![], 100);
        let b2 = chain.produce_block(b2contribs, vec![], 200);
        let b3 = chain.produce_block(b3contribs, vec![], 300);

        flush_block(store, &b1.block, &chain.state).unwrap();
        flush_block(store, &b3.block, &chain.state).unwrap();
        flush_block(store, &b2.block, &chain.state).unwrap();

        let control_chain = load_chain(store).unwrap();
        assert_eq!(control_chain.height, 3);
        assert_eq!(control_chain.last_block_hash, b3.block.hash());
        //assert_eq!(control_chain.state.total_contribution_units, 31000);
        assert_eq!(
            control_chain.state.total_contribution_units,
            chain.state.total_contribution_units
        );
    }
    #[test]
    fn bogus_block_storagejson() {
        let store = &temp_store();

        let bad_key = block_key(99); // BLOCK_STORAGE prefix + 99 in LE bytes
        store.put(&bad_key, b"not valid json").unwrap();
        assert!(matches!(load_chain(store), Err(LoadError::Corrupt(_))));
    }

    #[test]
    fn timestamp_outoforder() {
        let store = &temp_store();
        let mut chain = load_chain(store).unwrap();

        chain
            .state
            .register_asset_type(AssetType {
                id: AssetId::from("code"),
                name: String::from("code"),
                weight: 10,
            })
            .unwrap();

        let b1contribs = make_contributions(3);
        let b2contribs = make_contributions(4);
        let b3contribs = make_contributions(5);
        let _b1 = chain.produce_block(b1contribs, vec![], 100);
        let _b2 = chain.produce_block(b2contribs, vec![], 300);
        let _b3 = chain.produce_block(b3contribs, vec![], 200);
    }

    #[test]
    fn full_pipeline_review_produce_persist() {
        use cofi_contracts::charter::Charter;
        use cofi_contracts::validation::{
            PendingStatus, VoteCommitment, VoteReveal, compute_commitment,
        };
        use ed25519_dalek::{Signer, SigningKey};

        let store = temp_store();
        let mut chain = load_chain(&store).unwrap();

        chain
            .state
            .register_asset_type(AssetType {
                id: AssetId::from("code"),
                name: String::from("code"),
                weight: 10,
            })
            .unwrap();
        chain.state.apply_charter(Charter::default()).unwrap();

        let mut rng = rand::thread_rng();
        let alice_key = SigningKey::generate(&mut rng);
        let mut pool = ReviewPool::new();

        // -- Alice: bootstrap, no reviewers yet ------------------------------

        pool.submit(Contribution {
            contributor: "alice".into(),
            asset_type: AssetId::from("code"),
            amount: 10,
        });
        pool.auto_approve_if_no_reviewers(
            &chain.state.derive_reviewers(),
            &chain.state.contributor_units,
        );

        let result = chain.produce_from_pool(&mut pool, vec![], 100);
        assert_eq!(result.block.header.height, 1);
        assert_eq!(chain.state.contributor_units["alice"], 100);

        // Now Alice can register her key.
        chain
            .state
            .register_contributor_key("alice".into(), alice_key.verifying_key())
            .unwrap();

        // -- Bob's first contribution, reviewed by Alice ---------------------

        let bob_key = SigningKey::generate(&mut rng);

        let bob_id = pool.submit(Contribution {
            contributor: "bob".into(),
            asset_type: AssetId::from("code"),
            amount: 5,
        });

        // Alice is a reviewer — Bob's contribution is NOT auto-approved.
        pool.auto_approve_if_no_reviewers(
            &chain.state.derive_reviewers(),
            &chain.state.contributor_units,
        );
        assert_eq!(pool.pending[0].status, PendingStatus::Pending);

        // Bob cannot self-approve (he has no key registered, so
        // ReviewerNotRegistered, not SelfApproval).
        let reviewers = chain.state.derive_reviewers();

        // Alice reviews Bob.
        let salt = [42u8; 32];
        let commitment =
            compute_commitment(bob_id, &alice_key.verifying_key(), true, &salt);
        let signature = alice_key.sign(&commitment);
        pool.commit_vote(
            bob_id,
            VoteCommitment {
                reviewer: alice_key.verifying_key(),
                commitment,
                signature,
            },
            &reviewers,
            &chain.state.contributor_units,
        )
        .unwrap();

        let outcome = pool
            .reveal_vote(
                bob_id,
                VoteReveal {
                    reviewer: alice_key.verifying_key(),
                    approve: true,
                    salt,
                },
                &chain.state.quorum_config,
                &reviewers,
            )
            .unwrap();
        assert_eq!(outcome.status, PendingStatus::Approved);

        let result = chain.produce_from_pool(&mut pool, vec![], 200);
        assert_eq!(result.block.header.height, 2);
        assert!(chain.state.contributor_units["bob"] > 0);

        // Bob registers his key after getting units.
        chain
            .state
            .register_contributor_key("bob".into(), bob_key.verifying_key())
            .unwrap();

        let reviewers = chain.state.derive_reviewers();
        assert_eq!(reviewers.len(), 2);

        // -- Persist and reload roundtrip ------------------------------------

        flush_block(&store, &result.block, &chain.state).unwrap();
        let restored = load_chain(&store).unwrap();
        assert_eq!(restored.height, 2);
        assert_eq!(
            restored.state.contributor_units.get("bob").copied(),
            chain.state.contributor_units.get("bob").copied(),
        );
    }

    // -- Redemption-in-block tests --------------------------------------------

    fn sign_redemption(key: &SigningKey, contributor: &str, amount: u64) -> Redemption {
        use cofi_contracts::redemption_message;
        let msg = redemption_message(contributor, amount);
        Redemption {
            contributor: contributor.into(),
            amount,
            signature: key.sign(&msg),
        }
    }

    #[test]
    fn body_hash_includes_redemptions() {
        let mut rng = rand::thread_rng();
        let key = SigningKey::generate(&mut rng);
        let contribs: Vec<Contribution> = vec![];

        let r1 = sign_redemption(&key, "alice", 10);
        let r2 = sign_redemption(&key, "alice", 20);

        let h1 = compute_body_hash(&contribs, &vec![r1.clone()]);
        let h2 = compute_body_hash(&contribs, &vec![r2.clone()]);
        assert_ne!(h1, h2);

        // Same redemptions, same hash.
        let h1_again = compute_body_hash(&contribs, &vec![r1]);
        assert_eq!(h1, h1_again);
    }

    #[test]
    fn produce_block_with_redemptions() {
        let mut chain = Chain::genesis();
        let mut rng = rand::thread_rng();
        let key = SigningKey::generate(&mut rng);

        chain
            .state
            .register_asset_type(AssetType {
                id: AssetId::from("code"),
                name: String::from("code"),
                weight: 10,
            })
            .unwrap();

        // Block 1: alice contributes.
        chain
            .produce_block(
                vec![Contribution {
                    contributor: "alice".into(),
                    asset_type: "code".into(),
                    amount: 10,
                }],
                vec![],
                100,
            );

        assert_eq!(chain.state.contributor_units["alice"], 100);
        assert_eq!(chain.state.total_contribution_units, 100);
        assert_eq!(chain.state.total_asset_units, 100);

        // Register key so alice can redeem.
        chain
            .state
            .register_contributor_key("alice".into(), key.verifying_key())
            .unwrap();

        // Block 2: alice redeems 30 units.
        let redemptions = vec![sign_redemption(&key, "alice", 30)];
        let result = chain.produce_block(vec![], redemptions, 200);

        assert_eq!(result.block.header.height, 2);
        assert_eq!(result.block.redemptions.len(), 1);
        assert_eq!(result.block.contributions.len(), 0);
        assert_eq!(result.redemption_results.len(), 1);
        assert!(result.redemption_results[0].is_ok());

        let rr = result.redemption_results[0].as_ref().unwrap();
        assert_eq!(rr.contribution_units_burned, 30);
        assert_eq!(rr.asset_units_returned, 30);

        assert_eq!(chain.state.contributor_units["alice"], 70);
        assert_eq!(chain.state.total_contribution_units, 70);
        assert_eq!(chain.state.total_asset_units, 70);
    }

    #[test]
    fn invalid_redemption_skipped_in_block() {
        let mut chain = Chain::genesis();
        let mut rng = rand::thread_rng();
        let key = SigningKey::generate(&mut rng);

        chain
            .state
            .register_asset_type(AssetType {
                id: AssetId::from("code"),
                name: String::from("code"),
                weight: 10,
            })
            .unwrap();

        // Give alice units and a key.
        chain
            .produce_block(
                vec![Contribution {
                    contributor: "alice".into(),
                    asset_type: "code".into(),
                    amount: 10,
                }],
                vec![],
                100,
            );
        chain
            .state
            .register_contributor_key("alice".into(), key.verifying_key())
            .unwrap();

        // Try to redeem more than alice has.
        let redemptions = vec![sign_redemption(&key, "alice", 999)];
        let result = chain.produce_block(vec![], redemptions, 200);

        assert_eq!(result.block.redemptions.len(), 0);
        assert_eq!(result.redemption_results.len(), 1);
        assert!(result.redemption_results[0].is_err());

        // State unchanged.
        assert_eq!(chain.state.contributor_units["alice"], 100);
        assert_eq!(chain.state.total_contribution_units, 100);
    }

    #[test]
    fn redemption_roundtrip_through_persistence() {
        let store = temp_store();
        let mut chain = load_chain(&store).unwrap();
        let mut rng = rand::thread_rng();
        let key = SigningKey::generate(&mut rng);

        chain
            .state
            .register_asset_type(AssetType {
                id: AssetId::from("code"),
                name: String::from("code"),
                weight: 10,
            })
            .unwrap();

        // Block 1: contribute.
        let r1 = chain.produce_block(
            vec![Contribution {
                contributor: "alice".into(),
                asset_type: "code".into(),
                amount: 10,
            }],
            vec![],
            100,
        );
        flush_block(&store, &r1.block, &chain.state).unwrap();

        chain
            .state
            .register_contributor_key("alice".into(), key.verifying_key())
            .unwrap();

        // Block 2: redeem.
        let r2 = chain.produce_block(
            vec![],
            vec![sign_redemption(&key, "alice", 40)],
            200,
        );
        flush_block(&store, &r2.block, &chain.state).unwrap();

        // Reload and verify state.
        let restored = load_chain(&store).unwrap();
        assert_eq!(restored.height, 2);
        assert_eq!(restored.state.contributor_units["alice"], 60);
        assert_eq!(restored.state.total_contribution_units, 60);
        assert_eq!(restored.state.total_asset_units, 60);
    }
}
