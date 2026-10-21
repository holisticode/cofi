use crate::validation::QuorumConfig;
use crate::{AssetId, AssetType, ContributorId};
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Governance configuration
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernanceConfig {
    /// How many state operations a proposal stays open for voting.
    pub voting_duration: u64,
    /// Percentage of votes cast that must approve (0–100).
    pub pass_threshold_percent: u8,
    /// Percentage of total voting power that must participate (0–100).
    pub quorum_percent: u8,
}

impl Default for GovernanceConfig {
    fn default() -> Self {
        Self {
            voting_duration: 100,
            pass_threshold_percent: 51,
            quorum_percent: 20,
        }
    }
}

// ---------------------------------------------------------------------------
// Contributor type
// ---------------------------------------------------------------------------

pub type ContributorTypeId = String;

/// A contributor role whose multipliers compound into an effective weight.
///
/// Each multiplier is in basis points (100 = 1.0×). The `compound()` method
/// multiplies them together, normalizing back to basis points.
///
/// ## Extensibility
///
/// Fields marked *automatic* are computed by the system, not set by
/// governance. Today they return identity (100 = 1.0×) — the stubs live in
/// [`super::CoFiState`] methods like `compute_seniority` and
/// `compute_reputation`. When those methods are implemented, the values
/// here are overwritten each time the contributor's state is evaluated.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContributorType {
    pub id: ContributorTypeId,
    pub name: String,
    /// Governance-set base weight (basis points). Defaults to 100 (1.0×).
    pub base_rate: u64,
    /// *Automatic* — grows with membership duration. Stub: 100.
    #[serde(default = "default_mul")]
    pub seniority: u64,
    /// *Automatic* — peer-review quality score. Stub: 100.
    #[serde(default = "default_mul")]
    pub reputation: u64,
    /// Governance-set demand signal for this role. Stub: 100.
    #[serde(default = "default_mul")]
    pub demand: u64,
}

fn default_mul() -> u64 {
    100
}

impl ContributorType {
    pub fn new(id: ContributorTypeId, name: String, base_rate: u64) -> Self {
        Self {
            id,
            name,
            base_rate,
            seniority: 100,
            reputation: 100,
            demand: 100,
        }
    }

    /// Compound all multipliers into a single factor (basis points).
    ///
    /// Four values each in basis points → product of four → divide by
    /// 100³ to normalize back to basis points. Uses u128 intermediates
    /// to avoid overflow.
    pub fn compound(&self) -> u64 {
        let product = self.base_rate as u128
            * self.seniority as u128
            * self.reputation as u128
            * self.demand as u128;
        (product / 1_000_000) as u64
    }
}

// ---------------------------------------------------------------------------
// Proposal
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProposalAction {
    // -- Asset types --
    RegisterAssetType(AssetType),
    UpdateAssetWeight {
        asset_id: AssetId,
        new_weight: u64,
    },
    RemoveAssetType(AssetId),

    // -- Contributor types --
    RegisterContributorType(ContributorType),
    UpdateContributorBaseRate {
        type_id: ContributorTypeId,
        new_base_rate: u64,
    },
    UpdateContributorDemand {
        type_id: ContributorTypeId,
        new_demand: u64,
    },
    RemoveContributorType(ContributorTypeId),

    // -- Quorum config --
    UpdateQuorumConfig(QuorumConfig),

    // -- Contributor keys --
    RegisterContributorKey {
        contributor_id: ContributorId,
        public_key: VerifyingKey,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ProposalStatus {
    Active,
    Passed,
    Rejected,
    Executed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proposal {
    pub id: u64,
    pub proposer: ContributorId,
    pub action: ProposalAction,
    /// State height when this proposal was created (used for snapshots).
    pub created_height: u64,
    /// State height after which voting closes.
    pub end_height: u64,
    /// Total contribution units at creation time — quorum baseline.
    pub snapshot_total_contrib: u64,
    /// Per-contributor contribution units at creation — vote weight per voter.
    pub snapshot_contributor_units: HashMap<ContributorId, u64>,
    /// Voter → approve.
    pub votes: HashMap<ContributorId, bool>,
    pub status: ProposalStatus,
}

impl Proposal {
    pub fn is_active(&self, current_height: u64) -> bool {
        self.status == ProposalStatus::Active && current_height <= self.end_height
    }

    pub fn voting_is_closed(&self, current_height: u64) -> bool {
        current_height > self.end_height
    }

    pub fn vote_weight(&self, contributor: &ContributorId) -> u64 {
        self.snapshot_contributor_units
            .get(contributor)
            .copied()
            .unwrap_or(0)
    }
}

// ---------------------------------------------------------------------------
// Tally (pure function)
// ---------------------------------------------------------------------------

#[derive(Debug, PartialEq)]
pub struct TallyResult {
    pub total_votes: u64,
    pub approve_votes: u64,
    pub reject_votes: u64,
    pub participation_percent: u8,
    pub approval_percent: u8,
    pub passed: bool,
}

/// Evaluate a proposal's votes against the governance config. Pure — does not
/// mutate state.
pub fn tally(proposal: &Proposal, config: &GovernanceConfig) -> TallyResult {
    let total_power = proposal.snapshot_total_contrib;
    let mut approve = 0u64;
    let mut reject = 0u64;

    for (voter, &approve_vote) in &proposal.votes {
        let weight = proposal.vote_weight(voter);
        if weight == 0 {
            continue;
        }
        if approve_vote {
            approve += weight;
        } else {
            reject += weight;
        }
    }

    let total_votes = approve + reject;

    let participation = if total_power > 0 {
        ((total_votes as u128 * 100) / total_power as u128) as u8
    } else {
        0
    };

    let approval = if total_votes > 0 {
        ((approve as u128 * 100) / total_votes as u128) as u8
    } else {
        0
    };

    let passed =
        participation >= config.quorum_percent && approval >= config.pass_threshold_percent;

    TallyResult {
        total_votes,
        approve_votes: approve,
        reject_votes: reject,
        participation_percent: participation,
        approval_percent: approval,
        passed,
    }
}

// ---------------------------------------------------------------------------
// Proposal errors
// ---------------------------------------------------------------------------

#[derive(Debug, PartialEq)]
pub enum ProposalError {
    InsufficientVotingPower,
    AlreadyVoted,
    ProposalNotActive,
    VotingPeriodNotOver,
    AlreadyFinalized,
    NotPassed,
    AssetTypeAlreadyExists(AssetId),
    AssetTypeNotFound(AssetId),
    ContributorTypeAlreadyExists(ContributorTypeId),
    ContributorTypeNotFound(ContributorTypeId),
    InvalidWeight,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_config() -> GovernanceConfig {
        GovernanceConfig::default()
    }

    fn make_proposal(snapshot_total: u64, snapshot_units: HashMap<ContributorId, u64>) -> Proposal {
        Proposal {
            id: 1,
            proposer: "alice".into(),
            action: ProposalAction::UpdateAssetWeight {
                asset_id: "code".into(),
                new_weight: 20,
            },
            created_height: 0,
            end_height: 100,
            snapshot_total_contrib: snapshot_total,
            snapshot_contributor_units: snapshot_units,
            votes: HashMap::new(),
            status: ProposalStatus::Active,
        }
    }

    #[test]
    fn empty_votes_does_not_pass() {
        let p = make_proposal(1000, HashMap::from([("alice".into(), 500)]));
        let r = tally(&p, &default_config());
        assert!(!r.passed);
        assert_eq!(r.participation_percent, 0);
    }

    #[test]
    fn unanimous_approval_passes() {
        let mut p = make_proposal(
            500,
            HashMap::from([("alice".into(), 300), ("bob".into(), 200)]),
        );
        p.votes.insert("alice".into(), true);
        p.votes.insert("bob".into(), true);

        let r = tally(&p, &default_config());
        assert!(r.passed);
        assert_eq!(r.participation_percent, 100);
        assert_eq!(r.approval_percent, 100);
    }

    #[test]
    fn quorum_not_met_fails() {
        let mut p = make_proposal(
            1000,
            HashMap::from([("alice".into(), 100), ("bob".into(), 900)]),
        );
        // Only alice votes (10% participation, below 20% quorum).
        p.votes.insert("alice".into(), true);

        let r = tally(&p, &default_config());
        assert!(!r.passed);
        assert_eq!(r.participation_percent, 10);
    }

    #[test]
    fn threshold_not_met_fails() {
        let mut p = make_proposal(
            500,
            HashMap::from([("alice".into(), 300), ("bob".into(), 200)]),
        );
        // Alice (300 weight) votes no, Bob (200 weight) votes yes.
        // Approval = 200/500 = 40%, below 51% threshold → fails.
        p.votes.insert("alice".into(), false);
        p.votes.insert("bob".into(), true);

        let r = tally(&p, &default_config());
        assert!(!r.passed);
        assert_eq!(r.approval_percent, 40);
    }

    #[test]
    fn voter_with_no_weight_is_ignored() {
        let mut p = make_proposal(500, HashMap::from([("alice".into(), 300)]));
        p.votes.insert("alice".into(), true);
        p.votes.insert("bob".into(), false); // bob has 0 weight in snapshot

        let r = tally(&p, &default_config());
        // Only alice's vote counts: 300 approve, 0 reject, 100% approval.
        assert!(r.passed);
        assert_eq!(r.approve_votes, 300);
        assert_eq!(r.reject_votes, 0);
    }

    #[test]
    fn proposer_without_weight_cannot_pass_alone() {
        let p = make_proposal(1000, HashMap::from([("alice".into(), 0)]));
        let r = tally(&p, &default_config());
        assert!(!r.passed);
    }
}
