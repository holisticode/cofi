use governance::{
    ContributorType, ContributorTypeId, ProposalAction, ProposalError,
};

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use charter::Charter;
use validation::QuorumConfig;

pub mod charter;
pub mod governance;
pub mod merkle;
pub mod store;
pub mod validation;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

pub type AssetId = String;
pub type ContributorId = String;

// ---------------------------------------------------------------------------
// State key encoding
// ---------------------------------------------------------------------------

/// Discriminant bytes for typed state keys, shared by `StateKey` and the KV
/// store so prefix scans don't duplicate the constants.
pub mod key_prefix {
    pub const ROOT: u8 = 0x00;
    pub const ASSET_TYPE: u8 = 0x01;
    pub const CONTRIBUTOR_TYPE: u8 = 0x02;
    pub const CONTRIBUTOR_UNITS: u8 = 0x03;
    pub const TOTAL_ASSET: u8 = 0x04;
    pub const TOTAL_CONTRIB: u8 = 0x05;

    pub const CONTRIBUTOR_KEY: u8 = 0x06;
    pub const QUORUM_CONFIG: u8 = 0x07;
    pub const PENDING_CONTRIB: u8 = 0x08;

    pub const BLOCK_STORAGE: u8 = 0x20;
}

/// Typed key for a state entry — used in the Merkle tree and the KV store.
/// Encodes to `[discriminant] + id_bytes` (or just `[discriminant]` for totals).
#[derive(Debug, Clone, PartialEq)]
pub enum StateKey {
    AssetType(AssetId),
    ContributorType(ContributorTypeId),
    ContributorUnits(ContributorId),
    ContributorKey(ContributorId),
    QuorumConfig,
    TotalAsset,
    TotalContrib,
}

impl StateKey {
    pub fn encode(&self) -> Vec<u8> {
        match self {
            StateKey::AssetType(id) => tagged(key_prefix::ASSET_TYPE, id),
            StateKey::ContributorType(id) => tagged(key_prefix::CONTRIBUTOR_TYPE, id),
            StateKey::ContributorUnits(id) => tagged(key_prefix::CONTRIBUTOR_UNITS, id),
            StateKey::ContributorKey(id) => tagged(key_prefix::CONTRIBUTOR_KEY, id),
            StateKey::QuorumConfig => vec![key_prefix::QUORUM_CONFIG],
            StateKey::TotalAsset => vec![key_prefix::TOTAL_ASSET],
            StateKey::TotalContrib => vec![key_prefix::TOTAL_CONTRIB],
        }
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.is_empty() {
            return None;
        }
        match bytes[0] {
            key_prefix::ASSET_TYPE => Some(StateKey::AssetType(str_suffix(bytes)?)),
            key_prefix::CONTRIBUTOR_TYPE => Some(StateKey::ContributorType(str_suffix(bytes)?)),
            key_prefix::CONTRIBUTOR_UNITS => Some(StateKey::ContributorUnits(str_suffix(bytes)?)),
            key_prefix::CONTRIBUTOR_KEY => Some(StateKey::ContributorKey(str_suffix(bytes)?)),
            key_prefix::QUORUM_CONFIG => Some(StateKey::QuorumConfig),
            key_prefix::TOTAL_ASSET => Some(StateKey::TotalAsset),
            key_prefix::TOTAL_CONTRIB => Some(StateKey::TotalContrib),
            _ => None,
        }
    }
}

fn tagged(prefix: u8, id: &str) -> Vec<u8> {
    let mut v = Vec::with_capacity(1 + id.len());
    v.push(prefix);
    v.extend_from_slice(id.as_bytes());
    v
}

fn str_suffix(bytes: &[u8]) -> Option<String> {
    std::str::from_utf8(&bytes[1..]).ok().map(String::from)
}

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

#[derive(Debug, PartialEq)]
pub enum Error {
    AssetTypeNotFound(AssetId),
    AssetTypeAlreadyExists(AssetId),
    ZeroWeight(AssetId),
    ZeroAmount,
    ContributorTypeNotFound(ContributorTypeId),
    ContributorTypeAlreadyExists(ContributorTypeId),
    InvalidQuorumConfig,
    InsufficientContributionUnits {
        contributor: ContributorId,
        requested: u64,
        available: u64,
    },
    ContributorKeyNotFound(ContributorId),
    InvalidRedemptionSignature(ContributorId),
}

impl From<ProposalError> for Error {
    fn from(e: ProposalError) -> Self {
        match e {
            ProposalError::AssetTypeAlreadyExists(id) => Error::AssetTypeAlreadyExists(id),
            ProposalError::AssetTypeNotFound(id) => Error::AssetTypeNotFound(id),
            ProposalError::ContributorTypeAlreadyExists(id) => {
                Error::ContributorTypeAlreadyExists(id)
            }
            ProposalError::ContributorTypeNotFound(id) => Error::ContributorTypeNotFound(id),
            ProposalError::InvalidWeight => Error::ZeroWeight(String::new()),
            _ => panic!("proposal error not convertible to state error: {e:?}"),
        }
    }
}

// ---------------------------------------------------------------------------
// Domain structs
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetType {
    pub id: AssetId,
    pub name: String,
    /// Normalization weight: converts one unit of this asset into the
    /// system's internal value unit. Higher weight = more valuable.
    pub weight: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Contribution {
    pub contributor: ContributorId,
    pub asset_type: AssetId,
    pub amount: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ContributionResult {
    /// Value units added to the asset layer: `amount * asset_weight`.
    pub asset_units: u64,
    /// Governance units added to the contribution layer, computed via the
    /// pro-rata formula against existing state.
    pub contribution_units: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Redemption {
    pub contributor: ContributorId,
    /// Amount of contribution units to burn.
    pub amount: u64,
    /// Ed25519 signature over `redemption_message(contributor, amount)`.
    pub signature: Signature,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RedemptionResult {
    /// Contribution units burned.
    pub contribution_units_burned: u64,
    /// Asset units returned, computed as the inverse of the contribution
    /// pro-rata formula.
    pub asset_units_returned: u64,
}

// ---------------------------------------------------------------------------
// State machine
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoFiState {
    pub asset_types: HashMap<AssetId, AssetType>,
    pub contributor_types: HashMap<ContributorTypeId, ContributorType>,
    pub contributor_units: HashMap<ContributorId, u64>,
    /// Ed25519 public key per contributor, enabling signature verification
    /// during review. Key registration is a direct state mutation — anyone
    /// can register, since keys alone grant no voting power.
    pub contributor_keys: HashMap<ContributorId, VerifyingKey>,
    /// Proportional quorum for contribution review. Set by charter,
    /// modifiable via governance.
    pub quorum_config: QuorumConfig,
    pub total_asset_units: u64,
    pub total_contribution_units: u64,
}

impl Default for CoFiState {
    fn default() -> Self {
        Self {
            asset_types: HashMap::new(),
            contributor_types: HashMap::new(),
            contributor_units: HashMap::new(),
            contributor_keys: HashMap::new(),
            quorum_config: QuorumConfig::default(),
            total_asset_units: 0,
            total_contribution_units: 0,
        }
    }
}

impl CoFiState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register_asset_type(&mut self, asset_type: AssetType) -> Result<(), Error> {
        if asset_type.weight == 0 {
            return Err(Error::ZeroWeight(asset_type.id));
        }
        if self.asset_types.contains_key(&asset_type.id) {
            return Err(Error::AssetTypeAlreadyExists(asset_type.id));
        }
        self.asset_types.insert(asset_type.id.clone(), asset_type);
        Ok(())
    }

    pub fn process_contribution(
        &mut self,
        contribution: Contribution,
    ) -> Result<ContributionResult, Error> {
        if contribution.amount == 0 {
            return Err(Error::ZeroAmount);
        }

        let asset_type = self
            .asset_types
            .get(&contribution.asset_type)
            .ok_or_else(|| Error::AssetTypeNotFound(contribution.asset_type.clone()))?;

        // Asset layer: normalize the contribution into internal value units.
        let asset_units = contribution
            .amount
            .checked_mul(asset_type.weight)
            .expect("overflow in asset_units calculation");

        // Contribution layer: pro-rata governance allocation.
        let contribution_units = compute_contribution_units(
            asset_units,
            self.total_asset_units,
            self.total_contribution_units,
        );

        // Update state.
        self.total_asset_units = self
            .total_asset_units
            .checked_add(asset_units)
            .expect("overflow in total_asset_units");

        self.total_contribution_units = self
            .total_contribution_units
            .checked_add(contribution_units)
            .expect("overflow in total_contribution_units");

        *self
            .contributor_units
            .entry(contribution.contributor)
            .or_insert(0) += contribution_units;

        Ok(ContributionResult {
            asset_units,
            contribution_units,
        })
    }

    /// Redeem contribution units for asset units.
    ///
    /// Burns the contributor's governance power and returns the equivalent
    /// asset-layer value. The exchange rate is the current pool ratio:
    ///
    /// ```text
    ///   asset_units = contribution_units × total_asset / total_contrib
    /// ```
    ///
    /// The contributor must have a registered key, and must sign the redemption
    /// message to prove they authorize burning their own units.
    pub fn process_redemption(
        &mut self,
        redemption: Redemption,
    ) -> Result<RedemptionResult, Error> {
        if redemption.amount == 0 {
            return Err(Error::ZeroAmount);
        }

        if self.total_contribution_units == 0 {
            return Err(Error::InsufficientContributionUnits {
                contributor: redemption.contributor.clone(),
                requested: redemption.amount,
                available: 0,
            });
        }

        // Verify the contributor has enough units.
        let available = self
            .contributor_units
            .get(&redemption.contributor)
            .copied()
            .unwrap_or(0);
        if available < redemption.amount {
            return Err(Error::InsufficientContributionUnits {
                contributor: redemption.contributor.clone(),
                requested: redemption.amount,
                available,
            });
        }

        // Verify the signature against the contributor's registered key.
        let verifying_key = self
            .contributor_keys
            .get(&redemption.contributor)
            .ok_or_else(|| Error::ContributorKeyNotFound(redemption.contributor.clone()))?;

        let msg = redemption_message(&redemption.contributor, redemption.amount);
        verifying_key
            .verify(&msg, &redemption.signature)
            .map_err(|_| Error::InvalidRedemptionSignature(redemption.contributor.clone()))?;

        // Compute asset units via the inverse formula.
        let asset_units = compute_asset_units(
            redemption.amount,
            self.total_asset_units,
            self.total_contribution_units,
        );

        // Burn contribution units.
        *self
            .contributor_units
            .get_mut(&redemption.contributor)
            .expect("contributor must exist") -= redemption.amount;
        self.total_contribution_units -= redemption.amount;
        self.total_asset_units -= asset_units;

        Ok(RedemptionResult {
            contribution_units_burned: redemption.amount,
            asset_units_returned: asset_units,
        })
    }

    // -- Contributor types --------------------------------------------------

    pub fn register_contributor_type(&mut self, ct: ContributorType) -> Result<(), Error> {
        if self.contributor_types.contains_key(&ct.id) {
            return Err(Error::ContributorTypeAlreadyExists(ct.id));
        }
        self.contributor_types.insert(ct.id.clone(), ct);
        Ok(())
    }

    pub fn update_contributor_base_rate(
        &mut self,
        type_id: &ContributorTypeId,
        new_base_rate: u64,
    ) -> Result<(), Error> {
        let ct = self
            .contributor_types
            .get_mut(type_id)
            .ok_or_else(|| Error::ContributorTypeNotFound(type_id.clone()))?;
        ct.base_rate = new_base_rate;
        Ok(())
    }

    pub fn update_contributor_demand(
        &mut self,
        type_id: &ContributorTypeId,
        new_demand: u64,
    ) -> Result<(), Error> {
        let ct = self
            .contributor_types
            .get_mut(type_id)
            .ok_or_else(|| Error::ContributorTypeNotFound(type_id.clone()))?;
        ct.demand = new_demand;
        Ok(())
    }

    pub fn remove_contributor_type(&mut self, type_id: &ContributorTypeId) -> Result<(), Error> {
        if self.contributor_types.remove(type_id).is_none() {
            return Err(Error::ContributorTypeNotFound(type_id.clone()));
        }
        Ok(())
    }

    // -- Asset type management -----------------------------------------------

    pub fn update_asset_weight(
        &mut self,
        asset_id: &AssetId,
        new_weight: u64,
    ) -> Result<(), Error> {
        if new_weight == 0 {
            return Err(Error::ZeroWeight(asset_id.clone()));
        }
        let at = self
            .asset_types
            .get_mut(asset_id)
            .ok_or_else(|| Error::AssetTypeNotFound(asset_id.clone()))?;
        at.weight = new_weight;
        Ok(())
    }

    pub fn remove_asset_type(&mut self, asset_id: &AssetId) -> Result<(), Error> {
        if self.asset_types.remove(asset_id).is_none() {
            return Err(Error::AssetTypeNotFound(asset_id.clone()));
        }
        Ok(())
    }

    // -- Charter --------------------------------------------------------------

    /// Apply genesis configuration. Call once when the chain is created.
    pub fn apply_charter(&mut self, charter: Charter) -> Result<(), Error> {
        self.quorum_config = charter.quorum_config;
        Ok(())
    }

    // -- Contributor keys -----------------------------------------------------

    /// Register an Ed25519 public key for a contributor.
    ///
    /// Only contributors with non-zero units can register a key, since
    /// reviewing requires skin in the game.
    pub fn register_contributor_key(
        &mut self,
        id: ContributorId,
        key: VerifyingKey,
    ) -> Result<(), Error> {
        let units = self.contributor_units.get(&id).copied().unwrap_or(0);
        if units == 0 {
            return Err(Error::ZeroAmount);
        }
        self.contributor_keys.insert(id, key);
        Ok(())
    }

    /// Build the reverse mapping needed by the review pool: VerifyingKey →
    /// ContributorId, for all contributors with non-zero units and a
    /// registered key.
    pub fn derive_reviewers(&self) -> HashMap<VerifyingKey, ContributorId> {
        let mut reviewers = HashMap::new();
        for (id, key) in &self.contributor_keys {
            if self.contributor_units.get(id).copied().unwrap_or(0) > 0 {
                reviewers.insert(*key, id.clone());
            }
        }
        reviewers
    }

    // -- Quorum config --------------------------------------------------------

    pub fn update_quorum_config(&mut self, config: QuorumConfig) -> Result<(), Error> {
        if config.numerator == 0 || config.denominator == 0 {
            return Err(Error::InvalidQuorumConfig);
        }
        self.quorum_config = config;
        Ok(())
    }

    // -- Proposal execution --------------------------------------------------

    pub fn apply_proposal_action(&mut self, action: &ProposalAction) -> Result<(), Error> {
        match action {
            ProposalAction::RegisterAssetType(at) => self.register_asset_type(at.clone()),
            ProposalAction::UpdateAssetWeight {
                asset_id,
                new_weight,
            } => self.update_asset_weight(asset_id, *new_weight),
            ProposalAction::RemoveAssetType(id) => self.remove_asset_type(id),
            ProposalAction::RegisterContributorType(ct) => {
                self.register_contributor_type(ct.clone())
            }
            ProposalAction::UpdateContributorBaseRate {
                type_id,
                new_base_rate,
            } => self.update_contributor_base_rate(type_id, *new_base_rate),
            ProposalAction::UpdateContributorDemand {
                type_id,
                new_demand,
            } => self.update_contributor_demand(type_id, *new_demand),
            ProposalAction::RemoveContributorType(id) => self.remove_contributor_type(id),
            ProposalAction::UpdateQuorumConfig(config) => self.update_quorum_config(config.clone()),
            ProposalAction::RegisterContributorKey {
                contributor_id,
                public_key,
            } => self.register_contributor_key(contributor_id.clone(), *public_key),
        }
    }

    /// Compute the Merkle root over the entire state.
    ///
    /// Collects every key-value pair in the state, sorts by key, and builds a
    /// binary Merkle tree. The root is a cryptographic commitment to the
    /// entire state — it gets committed to blocks so light clients can verify
    /// state proofs.
    pub fn state_root(&self) -> [u8; 32] {
        let mut entries: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();

        for (id, at) in &self.asset_types {
            let value = serde_json::to_vec(at).expect("AssetType serialization is infallible");
            entries.push((StateKey::AssetType(id.clone()).encode(), value));
        }

        for (id, ct) in &self.contributor_types {
            let value =
                serde_json::to_vec(ct).expect("ContributorType serialization is infallible");
            entries.push((StateKey::ContributorType(id.clone()).encode(), value));
        }

        for (id, &units) in &self.contributor_units {
            entries.push((
                StateKey::ContributorUnits(id.clone()).encode(),
                units.to_le_bytes().to_vec(),
            ));
        }

        for (id, key) in &self.contributor_keys {
            let value = serde_json::to_vec(key).expect("VerifyingKey serialization is infallible");
            entries.push((StateKey::ContributorKey(id.clone()).encode(), value));
        }

        let quorum_value = serde_json::to_vec(&self.quorum_config)
            .expect("QuorumConfig serialization is infallible");
        entries.push((StateKey::QuorumConfig.encode(), quorum_value));

        entries.push((
            StateKey::TotalAsset.encode(),
            self.total_asset_units.to_le_bytes().to_vec(),
        ));
        entries.push((
            StateKey::TotalContrib.encode(),
            self.total_contribution_units.to_le_bytes().to_vec(),
        ));

        merkle::merkle_root(&mut entries)
    }
}

// ---------------------------------------------------------------------------
// Pure functions
// ---------------------------------------------------------------------------

/// Compute contribution-layer units from asset-layer units.
///
/// `asset_units` — value of *this* contribution in the asset layer.
/// `current_total_asset` — `total_asset_units` **before** this contribution.
/// `current_total_contrib` — `total_contribution_units` **before** this
/// contribution.
///
/// For the first contribution ever (`current_total_asset == 0`), the mapping
/// is 1:1 — this establishes the initial ratio between the two layers.
/// Subsequent contributions get a pro-rata share of existing governance
/// power:
///
/// ```text
///   contribution_units = asset_units × current_total_contrib / current_total_asset
/// ```
///
/// This means early contributors earn more governance per unit of real-world
/// value, since the denominator (total_asset_units) grows over time.
pub fn compute_contribution_units(
    asset_units: u64,
    current_total_asset: u64,
    current_total_contrib: u64,
) -> u64 {
    if current_total_asset == 0 {
        // First contribution ever — seed the ratio at 1:1.
        asset_units
    } else {
        ((asset_units as u128 * current_total_contrib as u128) / current_total_asset as u128) as u64
    }
}

/// Build the message that gets signed for a redemption.
///
/// Domain-separated with the literal `redemption:` prefix so a signature
/// produced for one context (review, governance) can't be replayed as a
/// redemption.
pub fn redemption_message(contributor: &str, amount: u64) -> Vec<u8> {
    let mut msg = Vec::with_capacity(11 + contributor.len() + 8);
    msg.extend_from_slice(b"redemption:");
    msg.extend_from_slice(contributor.as_bytes());
    msg.extend_from_slice(&amount.to_le_bytes());
    msg
}

/// Compute asset units from contribution units — the inverse of
/// `compute_contribution_units`.
///
/// `contribution_units` — governance units being burned.
/// `current_total_asset` — `total_asset_units` **before** this redemption.
/// `current_total_contrib` — `total_contribution_units` **before** this
/// redemption.
///
/// ```text
///   asset_units = contribution_units × current_total_asset / current_total_contrib
/// ```
///
/// This is the same pool ratio as the forward formula, just inverted. Early
/// redeemers get less value than late redeemers because the asset pool shrinks
/// relative to the contribution pool over time.
pub fn compute_asset_units(
    contribution_units: u64,
    current_total_asset: u64,
    current_total_contrib: u64,
) -> u64 {
    debug_assert!(current_total_contrib > 0, "no contribution units to redeem against");
    ((contribution_units as u128 * current_total_asset as u128) / current_total_contrib as u128)
        as u64
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Signer;
    use ed25519_dalek::SigningKey;

    fn setup_state() -> CoFiState {
        let mut state = CoFiState::new();
        state
            .register_asset_type(AssetType {
                id: "code".into(),
                name: "Code contribution".into(),
                weight: 10,
            })
            .unwrap();
        state
            .register_asset_type(AssetType {
                id: "hardware".into(),
                name: "Hardware donation".into(),
                weight: 50,
            })
            .unwrap();
        state
    }

    // -- Formula unit tests -------------------------------------------------

    #[test]
    fn first_contribution_establishes_one_to_one_ratio() {
        let units = compute_contribution_units(100, 0, 0);
        assert_eq!(units, 100);
    }

    #[test]
    fn pro_rata_against_existing_pool() {
        // Existing: 900 asset units, 100 contribution units.
        // New contribution adds 100 asset units = 1/9 of existing pool.
        // Earns 100 * 100 / 900 = 11 contribution units (integer division).
        let units = compute_contribution_units(100, 900, 100);
        assert_eq!(units, 11);
    }

    // -- Full state machine tests -------------------------------------------

    #[test]
    fn register_asset_type_and_contribute() {
        let mut state = setup_state();

        let result = state
            .process_contribution(Contribution {
                contributor: "alice".into(),
                asset_type: "code".into(),
                amount: 5,
            })
            .unwrap();

        assert_eq!(result.asset_units, 50); // 5 × weight 10
        assert_eq!(result.contribution_units, 50); // first → 1:1

        assert_eq!(state.total_asset_units, 50);
        assert_eq!(state.total_contribution_units, 50);
        assert_eq!(state.contributor_units["alice"], 50);
    }

    #[test]
    fn second_contributor_gets_pro_rata_share() {
        let mut state = setup_state();

        // Alice: 10 code = 100 asset, 100 contribution (1:1 seed).
        state
            .process_contribution(Contribution {
                contributor: "alice".into(),
                asset_type: "code".into(),
                amount: 10,
            })
            .unwrap();

        // Bob: 2 hardware = 100 asset.
        // Pool before Bob: 100 asset, 100 contrib.
        // Bob contrib: 100 * 100 / 100 = 100.
        let result = state
            .process_contribution(Contribution {
                contributor: "bob".into(),
                asset_type: "hardware".into(),
                amount: 2,
            })
            .unwrap();

        assert_eq!(result.asset_units, 100);
        assert_eq!(result.contribution_units, 100);

        assert_eq!(state.total_asset_units, 200);
        assert_eq!(state.total_contribution_units, 200);
        assert_eq!(state.contributor_units["alice"], 100);
        assert_eq!(state.contributor_units["bob"], 100);
    }

    #[test]
    fn late_contributor_gets_diluted() {
        let mut state = setup_state();

        // Alice seeds at 1:1.
        state
            .process_contribution(Contribution {
                contributor: "alice".into(),
                asset_type: "code".into(),
                amount: 1,
            })
            .unwrap();
        // State: 10 asset, 10 contrib. Ratio 1:1.

        // Simulate many contributions that shift the ratio.
        // Add 90 more asset units without adding contribution units.
        // This simulates what happens when the pool ratio changes over time
        // (not possible via normal process_contribution, but can happen if
        // weights are adjusted externally).
        state.total_asset_units += 990; // now 1000
        // Pool ratio is now 1000 asset : 10 contrib = 100:1.

        let result = state
            .process_contribution(Contribution {
                contributor: "bob".into(),
                asset_type: "code".into(),
                amount: 1,
            })
            .unwrap();

        // Bob: 10 asset units.
        // contrib = 10 * 10 / 1000 = 0 (integer division).
        assert_eq!(result.asset_units, 10);
        assert_eq!(result.contribution_units, 0);
    }

    // -- Error cases --------------------------------------------------------

    #[test]
    fn error_on_unknown_asset_type() {
        let mut state = setup_state();
        let err = state
            .process_contribution(Contribution {
                contributor: "alice".into(),
                asset_type: "nonexistent".into(),
                amount: 1,
            })
            .unwrap_err();
        assert_eq!(err, Error::AssetTypeNotFound("nonexistent".into()));
    }

    #[test]
    fn error_on_zero_amount() {
        let mut state = setup_state();
        let err = state
            .process_contribution(Contribution {
                contributor: "alice".into(),
                asset_type: "code".into(),
                amount: 0,
            })
            .unwrap_err();
        assert_eq!(err, Error::ZeroAmount);
    }

    #[test]
    fn error_on_zero_weight_asset() {
        let mut state = CoFiState::new();
        let err = state
            .register_asset_type(AssetType {
                id: "bad".into(),
                name: "Zero weight".into(),
                weight: 0,
            })
            .unwrap_err();
        assert_eq!(err, Error::ZeroWeight("bad".into()));
    }

    #[test]
    fn error_on_duplicate_asset_type() {
        let mut state = setup_state();
        let err = state
            .register_asset_type(AssetType {
                id: "code".into(),
                name: "Duplicate".into(),
                weight: 5,
            })
            .unwrap_err();
        assert_eq!(err, Error::AssetTypeAlreadyExists("code".into()));
    }

    // -- Redemption helpers ---------------------------------------------------

    fn setup_state_with_contributor(
        contributor: &str,
        contrib_amount: u64,
    ) -> (CoFiState, SigningKey) {
        let mut state = setup_state();
        let mut rng = rand::thread_rng();
        let key = SigningKey::generate(&mut rng);

        state
            .process_contribution(Contribution {
                contributor: contributor.into(),
                asset_type: "code".into(),
                amount: contrib_amount,
            })
            .unwrap();

        state
            .register_contributor_key(contributor.into(), key.verifying_key())
            .unwrap();

        (state, key)
    }

    fn sign_redemption(key: &SigningKey, contributor: &str, amount: u64) -> Redemption {
        let msg = redemption_message(contributor, amount);
        let signature = key.sign(&msg);
        Redemption {
            contributor: contributor.into(),
            amount,
            signature,
        }
    }

    // -- Redemption tests -----------------------------------------------------

    #[test]
    fn redeem_partial_units() {
        let (mut state, key) = setup_state_with_contributor("alice", 10);
        // Alice: 10 code × weight 10 = 100 asset, 100 contrib (1:1 seed).

        let redemption = sign_redemption(&key, "alice", 30);
        let result = state.process_redemption(redemption).unwrap();

        // Burn 30 contrib → return 30 * 100/100 = 30 asset.
        assert_eq!(result.contribution_units_burned, 30);
        assert_eq!(result.asset_units_returned, 30);

        assert_eq!(state.total_contribution_units, 70);
        assert_eq!(state.total_asset_units, 70);
        assert_eq!(state.contributor_units["alice"], 70);
    }

    #[test]
    fn redeem_all_units() {
        let (mut state, key) = setup_state_with_contributor("alice", 10);

        let redemption = sign_redemption(&key, "alice", 100);
        let result = state.process_redemption(redemption).unwrap();

        assert_eq!(result.contribution_units_burned, 100);
        assert_eq!(result.asset_units_returned, 100);
        assert_eq!(state.total_contribution_units, 0);
        assert_eq!(state.total_asset_units, 0);
        assert_eq!(state.contributor_units["alice"], 0);
    }

    #[test]
    fn redeem_with_pool_ratio_shifted() {
        let (mut state, key) = setup_state_with_contributor("alice", 10);
        // Alice seeded 100 asset, 100 contrib. Manually inflate the asset pool.
        state.total_asset_units = 1000;
        // Pool ratio: 1000 asset / 100 contrib = 10:1.

        let redemption = sign_redemption(&key, "alice", 10);
        let result = state.process_redemption(redemption).unwrap();

        // Burn 10 contrib → 10 * 1000/100 = 100 asset.
        assert_eq!(result.contribution_units_burned, 10);
        assert_eq!(result.asset_units_returned, 100);

        assert_eq!(state.total_contribution_units, 90);
        assert_eq!(state.total_asset_units, 900);
        assert_eq!(state.contributor_units["alice"], 90);
    }

    #[test]
    fn redeem_with_integer_truncation() {
        let (mut state, key) = setup_state_with_contributor("alice", 10);
        state.total_asset_units = 1000;
        // Pool ratio: 1000/100 = 10:1.

        // Redeem 1 contrib → 1 * 1000/100 = 10 asset. Exact.
        let r = sign_redemption(&key, "alice", 1);
        let result = state.process_redemption(r).unwrap();
        assert_eq!(result.asset_units_returned, 10);

        // Now: 990 asset / 99 contrib. Redeem 1 → 1 * 990/99 = 10 asset. Still exact.
        let r2 = sign_redemption(&key, "alice", 1);
        let result2 = state.process_redemption(r2).unwrap();
        assert_eq!(result2.asset_units_returned, 10);

        // State: 980 asset / 98 contrib. Shift by bumping asset to 987.
        state.total_asset_units = 987;
        // Redeem 1 contrib → 1 * 987/98 = 10.07... → 10 (truncated).
        let r3 = sign_redemption(&key, "alice", 1);
        let result3 = state.process_redemption(r3).unwrap();
        assert_eq!(result3.asset_units_returned, 10);
        assert_eq!(state.total_asset_units, 977);
        assert_eq!(state.total_contribution_units, 97);
    }

    #[test]
    fn redemption_error_zero_amount() {
        let (mut state, key) = setup_state_with_contributor("alice", 10);

        let r = sign_redemption(&key, "alice", 0);
        let err = state.process_redemption(r).unwrap_err();
        assert_eq!(err, Error::ZeroAmount);
    }

    #[test]
    fn redemption_error_insufficient_units() {
        let (mut state, key) = setup_state_with_contributor("alice", 1);
        // Alice has 1 × 10 = 10 asset, 10 contrib.

        let r = sign_redemption(&key, "alice", 999);
        let err = state.process_redemption(r).unwrap_err();
        assert_eq!(
            err,
            Error::InsufficientContributionUnits {
                contributor: "alice".into(),
                requested: 999,
                available: 10,
            }
        );
    }

    #[test]
    fn redemption_error_no_registered_key() {
        let mut state = setup_state();
        state
            .process_contribution(Contribution {
                contributor: "alice".into(),
                asset_type: "code".into(),
                amount: 10,
            })
            .unwrap();
        // Alice has units but no key.

        let r = Redemption {
            contributor: "alice".into(),
            amount: 5,
            signature: Signature::from_bytes(&[0u8; 64]),
        };

        let err = state.process_redemption(r).unwrap_err();
        assert_eq!(err, Error::ContributorKeyNotFound("alice".into()));
    }

    #[test]
    fn redemption_error_invalid_signature() {
        let (mut state, _key) = setup_state_with_contributor("alice", 10);
        let mut rng = rand::thread_rng();
        let other_key = SigningKey::generate(&mut rng);

        // Sign with the wrong key.
        let msg = redemption_message("alice", 30);
        let signature = other_key.sign(&msg);

        let r = Redemption {
            contributor: "alice".into(),
            amount: 30,
            signature,
        };

        let err = state.process_redemption(r).unwrap_err();
        assert_eq!(err, Error::InvalidRedemptionSignature("alice".into()));
    }

    #[test]
    fn redemption_error_wrong_contributor_in_message() {
        let (mut state, key) = setup_state_with_contributor("alice", 10);

        // Sign a message for "bob" but try to redeem as "alice".
        let msg = redemption_message("bob", 30);
        let signature = key.sign(&msg);

        let r = Redemption {
            contributor: "alice".into(),
            amount: 30,
            signature,
        };

        let err = state.process_redemption(r).unwrap_err();
        assert_eq!(err, Error::InvalidRedemptionSignature("alice".into()));
    }

    #[test]
    fn redemption_message_is_deterministic() {
        let m1 = redemption_message("alice", 42);
        let m2 = redemption_message("alice", 42);
        assert_eq!(m1, m2);
    }

    #[test]
    fn redemption_message_differs_by_amount() {
        let m1 = redemption_message("alice", 42);
        let m2 = redemption_message("alice", 43);
        assert_ne!(m1, m2);
    }

    #[test]
    fn redemption_message_differs_by_contributor() {
        let m1 = redemption_message("alice", 42);
        let m2 = redemption_message("bob", 42);
        assert_ne!(m1, m2);
    }

    #[test]
    fn redemption_total_consistency() {
        let (mut state, key) = setup_state_with_contributor("alice", 10);

        let before_asset = state.total_asset_units;
        let before_contrib = state.total_contribution_units;
        let before_alice = state.contributor_units["alice"];

        let r = sign_redemption(&key, "alice", 30);
        let result = state.process_redemption(r).unwrap();

        assert_eq!(
            state.total_contribution_units,
            before_contrib - result.contribution_units_burned
        );
        assert_eq!(
            state.total_asset_units,
            before_asset - result.asset_units_returned
        );
        assert_eq!(
            state.contributor_units["alice"],
            before_alice - result.contribution_units_burned
        );
    }
}
