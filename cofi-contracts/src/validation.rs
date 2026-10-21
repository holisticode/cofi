use crate::key_prefix;
use crate::store::StateStore;
use crate::{ContributorId, Contribution};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// QuorumConfig
// ---------------------------------------------------------------------------

/// Proportional quorum: `ceil(numerator × reviewers / denominator)` approvals
/// required. Set by the charter, modifiable via governance.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct QuorumConfig {
    pub numerator: u32,
    pub denominator: u32,
}

impl Default for QuorumConfig {
    fn default() -> Self {
        Self {
            numerator: 2,
            denominator: 3,
        }
    }
}

/// How many reviewers must approve given the total count.
///
/// Pure function. Formula: `ceil(numerator * total / denominator)`.
/// Returns at least 1 when there's at least 1 reviewer (bootstrap safeguard).
pub fn required_approvals(quorum: &QuorumConfig, total_reviewers: usize) -> u32 {
    if total_reviewers == 0 {
        return 0;
    }
    let n = quorum.numerator as u64;
    let d = quorum.denominator as u64;
    let t = total_reviewers as u64;
    // ceil(n * t / d) = (n * t + d - 1) / d
    let required = ((n * t + d - 1) / d) as u32;
    // Floor at 1 when reviewers exist — a lone reviewer should be able to
    // approve (bootstrap) rather than being permanently blocked.
    if required == 0 {
        1
    } else {
        required
    }
}

// ---------------------------------------------------------------------------
// Pending status
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PendingStatus {
    Pending,
    Approved,
    Rejected,
}

// ---------------------------------------------------------------------------
// Commit-reveal types
// ---------------------------------------------------------------------------

/// Phase 1: a reviewer commits to a vote without revealing it.
///
/// The `commitment` is `SHA-256(pending_id || reviewer.as_bytes() || approve_byte || salt)`.
/// The `signature` signs the commitment bytes, authenticating the reviewer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoteCommitment {
    pub reviewer: VerifyingKey,
    pub commitment: [u8; 32],
    pub signature: Signature,
}

/// Phase 2: a reviewer reveals their vote and salt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoteReveal {
    pub reviewer: VerifyingKey,
    pub approve: bool,
    pub salt: [u8; 32],
}

/// A vote that has been revealed and counted.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevealedVote {
    pub reviewer: VerifyingKey,
    pub approve: bool,
}

// ---------------------------------------------------------------------------
// Pending contribution
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingContribution {
    pub id: u64,
    pub contribution: Contribution,
    pub commitments: Vec<VoteCommitment>,
    pub revealed_votes: Vec<RevealedVote>,
    pub status: PendingStatus,
}

// ---------------------------------------------------------------------------
// Review outcome
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReviewOutcome {
    pub required_approvals: u32,
    pub current_approvals: u32,
    pub current_rejections: u32,
    pub total_reviewers: u32,
    pub status: PendingStatus,
}

// ---------------------------------------------------------------------------
// Pure function: evaluate_review
// ---------------------------------------------------------------------------

/// Count revealed votes and determine status against the quorum.
///
/// Only revealed votes count — unrevealed commitments are ignored.
/// The vote mechanism (commit-reveal, ZK, direct) is invisible here.
pub fn evaluate_review(
    pending: &PendingContribution,
    quorum: &QuorumConfig,
    total_reviewers: usize,
) -> ReviewOutcome {
    let mut approvals: u32 = 0;
    let mut rejections: u32 = 0;

    for v in &pending.revealed_votes {
        if v.approve {
            approvals += 1;
        } else {
            rejections += 1;
        }
    }

    let required = required_approvals(quorum, total_reviewers);

    let status = if approvals >= required {
        PendingStatus::Approved
    } else if rejections > (total_reviewers as u32).saturating_sub(required) {
        // Even if every remaining reviewer approved, can't reach required.
        PendingStatus::Rejected
    } else {
        PendingStatus::Pending
    };

    ReviewOutcome {
        required_approvals: required,
        current_approvals: approvals,
        current_rejections: rejections,
        total_reviewers: total_reviewers as u32,
        status,
    }
}

// ---------------------------------------------------------------------------
// Commit-reveal helpers
// ---------------------------------------------------------------------------

/// Build the message that gets hashed for a commitment.
fn commitment_message(
    pending_id: u64,
    reviewer: &VerifyingKey,
    approve: bool,
    salt: &[u8; 32],
) -> Vec<u8> {
    let mut msg = Vec::with_capacity(8 + 32 + 1 + 32);
    msg.extend_from_slice(&pending_id.to_le_bytes());
    msg.extend_from_slice(reviewer.as_bytes());
    msg.push(if approve { 1 } else { 0 });
    msg.extend_from_slice(salt);
    msg
}

/// Compute SHA-256 commitment for a vote.
pub fn compute_commitment(
    pending_id: u64,
    reviewer: &VerifyingKey,
    approve: bool,
    salt: &[u8; 32],
) -> [u8; 32] {
    let msg = commitment_message(pending_id, reviewer, approve, salt);
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&Sha256::digest(&msg));
    hash
}

// ---------------------------------------------------------------------------
// Validation error
// ---------------------------------------------------------------------------

#[derive(Debug, PartialEq)]
pub enum ValidationError {
    PendingContributionNotFound(u64),
    AlreadyCommitted,
    AlreadyRevealed,
    CommitmentNotFound,
    CommitmentMismatch,
    ReviewAlreadyFinalized(u64, PendingStatus),
    InsufficientVotingPower,
    ReviewerNotRegistered,
    InvalidCommitmentSignature,
    SelfApproval,
}

// ---------------------------------------------------------------------------
// ReviewPool
// ---------------------------------------------------------------------------

/// Mempool of contributions undergoing blind N-of-M review via commit-reveal.
///
/// The reviewer set is derived from `CoFiState` at call time — anyone with
/// non-zero contribution units is a reviewer. Quorum config also comes from
/// state so governance changes take effect immediately.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReviewPool {
    pub pending: Vec<PendingContribution>,
    pub next_id: u64,
}

impl ReviewPool {
    pub fn new() -> Self {
        Self {
            pending: Vec::new(),
            next_id: 1,
        }
    }

    /// Submit a contribution for review. Always starts `Pending`.
    /// Returns the assigned id.
    pub fn submit(&mut self, contribution: Contribution) -> u64 {
        let id = self.next_id;
        self.next_id += 1;

        self.pending.push(PendingContribution {
            id,
            contribution,
            commitments: Vec::new(),
            revealed_votes: Vec::new(),
            status: PendingStatus::Pending,
        });

        id
    }

    /// Auto-approve any pending contribution whose contributor is the only
    /// reviewer — there's nobody else who can review it.
    ///
    /// This handles the bootstrap case where the first contributor cannot
    /// self-approve (self-approval is blocked) but no other reviewers exist.
    pub fn auto_approve_if_no_reviewers(
        &mut self,
        reviewers: &HashMap<VerifyingKey, ContributorId>,
        contributor_units: &HashMap<ContributorId, u64>,
    ) {
        for p in &mut self.pending {
            if p.status != PendingStatus::Pending {
                continue;
            }
            let eligible = reviewers
                .iter()
                .filter(|(_, id)| {
                    *id != &p.contribution.contributor
                        && contributor_units.get(*id).copied().unwrap_or(0) > 0
                })
                .count();
            if eligible == 0 {
                p.status = PendingStatus::Approved;
            }
        }
    }

    /// Phase 1: record a blinded vote commitment.
    ///
    /// The reviewer must sign the commitment with their Ed25519 key. The
    /// signature proves authenticity — but the vote (approve/reject) stays
    /// hidden behind the hash.
    pub fn commit_vote(
        &mut self,
        pending_id: u64,
        commitment: VoteCommitment,
        reviewers: &HashMap<VerifyingKey, ContributorId>,
        voter_units: &HashMap<ContributorId, u64>,
    ) -> Result<(), ValidationError> {
        let pending = self
            .pending
            .iter_mut()
            .find(|p| p.id == pending_id)
            .ok_or(ValidationError::PendingContributionNotFound(pending_id))?;

        if pending.status != PendingStatus::Pending {
            return Err(ValidationError::ReviewAlreadyFinalized(
                pending_id,
                pending.status,
            ));
        }

        // Must be a registered reviewer.
        let contributor_id = reviewers
            .get(&commitment.reviewer)
            .ok_or(ValidationError::ReviewerNotRegistered)?;

        // Reviewer cannot approve their own contribution.
        if *contributor_id == pending.contribution.contributor {
            return Err(ValidationError::SelfApproval);
        }

        // Must have voting power.
        let power = voter_units.get(contributor_id).copied().unwrap_or(0);
        if power == 0 {
            return Err(ValidationError::InsufficientVotingPower);
        }

        // Must not have already committed or revealed.
        if pending
            .commitments
            .iter()
            .any(|c| c.reviewer == commitment.reviewer)
            || pending
                .revealed_votes
                .iter()
                .any(|v| v.reviewer == commitment.reviewer)
        {
            return Err(ValidationError::AlreadyCommitted);
        }

        // Verify the signature on the commitment.
        commitment
            .reviewer
            .verify(&commitment.commitment, &commitment.signature)
            .map_err(|_| ValidationError::InvalidCommitmentSignature)?;

        pending.commitments.push(commitment);
        Ok(())
    }

    /// Phase 2: reveal a previously committed vote.
    ///
    /// Verifies that `SHA-256(message) == stored_commitment`, records the
    /// revealed vote, and re-evaluates the quorum.
    pub fn reveal_vote(
        &mut self,
        pending_id: u64,
        reveal: VoteReveal,
        quorum: &QuorumConfig,
        reviewers: &HashMap<VerifyingKey, ContributorId>,
    ) -> Result<ReviewOutcome, ValidationError> {
        let pending = self
            .pending
            .iter_mut()
            .find(|p| p.id == pending_id)
            .ok_or(ValidationError::PendingContributionNotFound(pending_id))?;

        if pending.status != PendingStatus::Pending {
            return Err(ValidationError::ReviewAlreadyFinalized(
                pending_id,
                pending.status,
            ));
        }

        // Must not have already revealed.
        if pending
            .revealed_votes
            .iter()
            .any(|v| v.reviewer == reveal.reviewer)
        {
            return Err(ValidationError::AlreadyRevealed);
        }

        // Find and verify the commitment.
        let pos = pending
            .commitments
            .iter()
            .position(|c| c.reviewer == reveal.reviewer)
            .ok_or(ValidationError::CommitmentNotFound)?;

        let expected =
            compute_commitment(pending_id, &reveal.reviewer, reveal.approve, &reveal.salt);

        if pending.commitments[pos].commitment != expected {
            return Err(ValidationError::CommitmentMismatch);
        }

        // Remove the commitment, record the revealed vote.
        pending.commitments.remove(pos);
        pending.revealed_votes.push(RevealedVote {
            reviewer: reveal.reviewer,
            approve: reveal.approve,
        });

        let total = reviewers.len();
        let outcome = evaluate_review(pending, quorum, total);
        if outcome.status != PendingStatus::Pending {
            pending.status = outcome.status;
        }

        Ok(outcome)
    }

    /// Extract all approved contributions.
    pub fn drain_approved(&mut self) -> Vec<Contribution> {
        let (approved, rest): (Vec<_>, Vec<_>) = self
            .pending
            .drain(..)
            .partition(|p| p.status == PendingStatus::Approved);

        self.pending = rest;
        approved.into_iter().map(|p| p.contribution).collect()
    }

    /// Read-only peek at a pending contribution's review state.
    pub fn review_status(
        &self,
        pending_id: u64,
        quorum: &QuorumConfig,
        reviewers: &HashMap<VerifyingKey, ContributorId>,
    ) -> Option<ReviewOutcome> {
        let pending = self.pending.iter().find(|p| p.id == pending_id)?;
        Some(evaluate_review(pending, quorum, reviewers.len()))
    }

    /// Reject all pending contributions below the given id threshold.
    pub fn reject_stale(&mut self, threshold_id: u64) {
        for p in &mut self.pending {
            if p.id < threshold_id && p.status == PendingStatus::Pending {
                p.status = PendingStatus::Rejected;
            }
        }
    }
}

impl Default for ReviewPool {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Persistence
// ---------------------------------------------------------------------------

pub fn flush_pool<S: StateStore>(store: &S, pool: &ReviewPool) -> Result<(), S::Error> {
    let value = serde_json::to_vec(pool).expect("ReviewPool serialization is infallible");
    store.put(&[key_prefix::PENDING_CONTRIB], &value)
}

pub fn load_pool<S: StateStore>(store: &S) -> Result<ReviewPool, S::Error> {
    match store.get(&[key_prefix::PENDING_CONTRIB])? {
        Some(value) => Ok(serde_json::from_slice(&value)
            .expect("ReviewPool deserialization is infallible")),
        None => Ok(ReviewPool::default()),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::SledStore;
    use ed25519_dalek::Signer;
    use ed25519_dalek::SigningKey;

    fn temp_store() -> SledStore {
        let dir = tempfile::tempdir().unwrap();
        SledStore::open(dir.path()).unwrap()
    }

    fn make_contribution() -> Contribution {
        Contribution {
            contributor: "alice".into(),
            asset_type: "code".into(),
            amount: 10,
        }
    }

    fn make_reviewer_set(
        keys: &[SigningKey],
    ) -> (HashMap<VerifyingKey, ContributorId>, HashMap<ContributorId, u64>) {
        let mut reviewers = HashMap::new();
        let mut units = HashMap::new();
        for (i, k) in keys.iter().enumerate() {
            let id = format!("rev{i}");
            reviewers.insert(k.verifying_key(), id.clone());
            units.insert(id, 100);
        }
        (reviewers, units)
    }

    fn commit(
        pending_id: u64,
        key: &SigningKey,
        approve: bool,
        salt: &[u8; 32],
    ) -> VoteCommitment {
        let reviewer = key.verifying_key();
        let commitment = compute_commitment(pending_id, &reviewer, approve, salt);
        let signature = key.sign(&commitment);
        VoteCommitment {
            reviewer,
            commitment,
            signature,
        }
    }

    fn reveal(key: &SigningKey, approve: bool, salt: [u8; 32]) -> VoteReveal {
        VoteReveal {
            reviewer: key.verifying_key(),
            approve,
            salt,
        }
    }

    // -- Quorum ---------------------------------------------------------------

    #[test]
    fn quorum_2_of_3_with_3_reviewers() {
        let q = QuorumConfig::default();
        assert_eq!(required_approvals(&q, 3), 2);
    }

    #[test]
    fn quorum_2_of_3_with_1_reviewer_bootstrap() {
        let q = QuorumConfig::default();
        assert_eq!(required_approvals(&q, 1), 1);
    }

    #[test]
    fn quorum_2_of_3_with_2_reviewers() {
        let q = QuorumConfig::default();
        assert_eq!(required_approvals(&q, 2), 2);
    }

    #[test]
    fn quorum_2_of_3_with_5_reviewers() {
        let q = QuorumConfig::default();
        assert_eq!(required_approvals(&q, 5), 4);
    }

    #[test]
    fn quorum_2_of_3_with_10_reviewers() {
        let q = QuorumConfig::default();
        assert_eq!(required_approvals(&q, 10), 7);
    }

    #[test]
    fn quorum_1_of_1() {
        let q = QuorumConfig {
            numerator: 1,
            denominator: 1,
        };
        assert_eq!(required_approvals(&q, 5), 5);
    }

    #[test]
    fn quorum_1_of_2() {
        let q = QuorumConfig {
            numerator: 1,
            denominator: 2,
        };
        assert_eq!(required_approvals(&q, 3), 2); // ceil(1.5) = 2
        assert_eq!(required_approvals(&q, 4), 2);
        assert_eq!(required_approvals(&q, 5), 3); // ceil(2.5) = 3
    }

    #[test]
    fn quorum_zero_reviewers() {
        let q = QuorumConfig::default();
        assert_eq!(required_approvals(&q, 0), 0);
    }

    // -- Commit-reveal --------------------------------------------------------

    #[test]
    fn commitment_is_deterministic() {
        let mut rng = rand::thread_rng();
        let key = SigningKey::generate(&mut rng);
        let salt = [42u8; 32];
        let c1 = compute_commitment(1, &key.verifying_key(), true, &salt);
        let c2 = compute_commitment(1, &key.verifying_key(), true, &salt);
        assert_eq!(c1, c2);
    }

    #[test]
    fn different_salt_different_commitment() {
        let mut rng = rand::thread_rng();
        let key = SigningKey::generate(&mut rng);
        let c1 = compute_commitment(1, &key.verifying_key(), true, &[1u8; 32]);
        let c2 = compute_commitment(1, &key.verifying_key(), true, &[2u8; 32]);
        assert_ne!(c1, c2);
    }

    #[test]
    fn different_vote_different_commitment() {
        let mut rng = rand::thread_rng();
        let key = SigningKey::generate(&mut rng);
        let salt = [42u8; 32];
        let c_approve = compute_commitment(1, &key.verifying_key(), true, &salt);
        let c_reject = compute_commitment(1, &key.verifying_key(), false, &salt);
        assert_ne!(c_approve, c_reject);
    }

    #[test]
    fn commit_then_reveal_success() {
        let mut pool = ReviewPool::new();
        let mut rng = rand::thread_rng();
        let key = SigningKey::generate(&mut rng);
        let (reviewers, units) = make_reviewer_set(&[key.clone()]);
        let salt = [42u8; 32];

        let id = pool.submit(make_contribution());
        let c = commit(id, &key, true, &salt);
        pool.commit_vote(id, c, &reviewers, &units).unwrap();

        let outcome = pool
            .reveal_vote(id, reveal(&key, true, salt), &QuorumConfig::default(), &reviewers)
            .unwrap();
        assert_eq!(outcome.status, PendingStatus::Approved);
        assert_eq!(outcome.current_approvals, 1);
    }

    #[test]
    fn reveal_with_wrong_salt_fails() {
        let mut pool = ReviewPool::new();
        let mut rng = rand::thread_rng();
        let key = SigningKey::generate(&mut rng);
        let (reviewers, units) = make_reviewer_set(&[key.clone()]);

        let id = pool.submit(make_contribution());
        let c = commit(id, &key, true, &[1u8; 32]);
        pool.commit_vote(id, c, &reviewers, &units).unwrap();

        // Reveal with different salt.
        let err = pool
            .reveal_vote(
                id,
                reveal(&key, true, [2u8; 32]),
                &QuorumConfig::default(),
                &reviewers,
            )
            .unwrap_err();
        assert_eq!(err, ValidationError::CommitmentMismatch);
    }

    #[test]
    fn reveal_without_commit_fails() {
        let mut pool = ReviewPool::new();
        let mut rng = rand::thread_rng();
        let key = SigningKey::generate(&mut rng);
        let (reviewers, _) = make_reviewer_set(&[key.clone()]);

        let id = pool.submit(make_contribution());
        let err = pool
            .reveal_vote(
                id,
                reveal(&key, true, [42u8; 32]),
                &QuorumConfig::default(),
                &reviewers,
            )
            .unwrap_err();
        assert_eq!(err, ValidationError::CommitmentNotFound);
    }

    #[test]
    fn double_commit_fails() {
        let mut pool = ReviewPool::new();
        let mut rng = rand::thread_rng();
        let key = SigningKey::generate(&mut rng);
        let (reviewers, units) = make_reviewer_set(&[key.clone()]);

        let id = pool.submit(make_contribution());
        pool.commit_vote(id, commit(id, &key, true, &[1u8; 32]), &reviewers, &units)
            .unwrap();

        let err = pool
            .commit_vote(id, commit(id, &key, false, &[2u8; 32]), &reviewers, &units)
            .unwrap_err();
        assert_eq!(err, ValidationError::AlreadyCommitted);
    }

    #[test]
    fn double_reveal_fails() {
        let mut pool = ReviewPool::new();
        let mut rng = rand::thread_rng();
        let key = SigningKey::generate(&mut rng);
        let (reviewers, units) = make_reviewer_set(&[key.clone()]);
        let salt = [42u8; 32];

        let id = pool.submit(make_contribution());
        pool.commit_vote(id, commit(id, &key, true, &salt), &reviewers, &units)
            .unwrap();
        pool.reveal_vote(id, reveal(&key, true, salt), &QuorumConfig::default(), &reviewers)
            .unwrap();

        // Review is now approved (1-of-1 with single reviewer), second reveal
        // is rejected because the review is already finalized.
        let err = pool
            .reveal_vote(id, reveal(&key, false, salt), &QuorumConfig::default(), &reviewers)
            .unwrap_err();
        assert_eq!(
            err,
            ValidationError::ReviewAlreadyFinalized(id, PendingStatus::Approved)
        );
    }

    // -- Review pool ----------------------------------------------------------

    #[test]
    fn submit_starts_pending() {
        let mut pool = ReviewPool::new();
        let id = pool.submit(make_contribution());
        assert_eq!(id, 1);
        assert_eq!(pool.pending[0].status, PendingStatus::Pending);
        assert_eq!(pool.pending[0].contribution.amount, 10);
    }

    #[test]
    fn two_of_three_approves() {
        let mut pool = ReviewPool::new();
        let mut rng = rand::thread_rng();
        let keys: Vec<SigningKey> = (0..3).map(|_| SigningKey::generate(&mut rng)).collect();
        let (reviewers, units) = make_reviewer_set(&keys);
        let q = QuorumConfig::default();

        let id = pool.submit(make_contribution());

        // First reviewer commits + reveals approve.
        let salt1 = [1u8; 32];
        pool.commit_vote(id, commit(id, &keys[0], true, &salt1), &reviewers, &units)
            .unwrap();
        let o1 = pool
            .reveal_vote(id, reveal(&keys[0], true, salt1), &q, &reviewers)
            .unwrap();
        assert_eq!(o1.status, PendingStatus::Pending); // 1 of 2 needed

        // Second reviewer commits + reveals approve → hits threshold.
        let salt2 = [2u8; 32];
        pool.commit_vote(id, commit(id, &keys[1], true, &salt2), &reviewers, &units)
            .unwrap();
        let o2 = pool
            .reveal_vote(id, reveal(&keys[1], true, salt2), &q, &reviewers)
            .unwrap();
        assert_eq!(o2.status, PendingStatus::Approved);
        assert_eq!(o2.current_approvals, 2);
    }

    #[test]
    fn rejection_makes_it_mathematically_impossible() {
        let mut pool = ReviewPool::new();
        let mut rng = rand::thread_rng();
        let keys: Vec<SigningKey> = (0..3).map(|_| SigningKey::generate(&mut rng)).collect();
        let (reviewers, units) = make_reviewer_set(&keys);
        let q = QuorumConfig::default();

        let id = pool.submit(make_contribution());

        // 2-of-3 quorum. Two rejections means even if the third approves, only
        // 1 approval — can't reach 2. So 2 rejections → Rejected.

        let salt1 = [1u8; 32];
        pool.commit_vote(id, commit(id, &keys[0], false, &salt1), &reviewers, &units)
            .unwrap();
        pool.reveal_vote(id, reveal(&keys[0], false, salt1), &q, &reviewers)
            .unwrap();

        let salt2 = [2u8; 32];
        pool.commit_vote(id, commit(id, &keys[1], false, &salt2), &reviewers, &units)
            .unwrap();
        let o = pool
            .reveal_vote(id, reveal(&keys[1], false, salt2), &q, &reviewers)
            .unwrap();

        assert_eq!(o.status, PendingStatus::Rejected);
    }

    #[test]
    fn unregistered_reviewer_rejected() {
        let mut pool = ReviewPool::new();
        let mut rng = rand::thread_rng();
        let key = SigningKey::generate(&mut rng);

        let empty_reviewers: HashMap<VerifyingKey, ContributorId> = HashMap::new();
        let empty_units: HashMap<ContributorId, u64> = HashMap::new();

        let id = pool.submit(make_contribution());
        let c = commit(id, &key, true, &[42u8; 32]);
        let err = pool
            .commit_vote(id, c, &empty_reviewers, &empty_units)
            .unwrap_err();
        assert_eq!(err, ValidationError::ReviewerNotRegistered);
    }

    #[test]
    fn invalid_commitment_signature_rejected() {
        let mut pool = ReviewPool::new();
        let mut rng = rand::thread_rng();
        let key = SigningKey::generate(&mut rng);
        let other_key = SigningKey::generate(&mut rng);
        let (reviewers, units) = make_reviewer_set(&[key.clone()]);

        let id = pool.submit(make_contribution());

        // Build a commitment signed by other_key but claiming to be from key.
        let reviewer = key.verifying_key();
        let commitment = compute_commitment(id, &reviewer, true, &[42u8; 32]);
        let signature = other_key.sign(&commitment); // wrong signer!
        let c = VoteCommitment {
            reviewer,
            commitment,
            signature,
        };

        let err = pool.commit_vote(id, c, &reviewers, &units).unwrap_err();
        assert_eq!(err, ValidationError::InvalidCommitmentSignature);
    }

    #[test]
    fn no_voting_power_rejected() {
        let mut pool = ReviewPool::new();
        let mut rng = rand::thread_rng();
        let key = SigningKey::generate(&mut rng);

        let mut reviewers = HashMap::new();
        reviewers.insert(key.verifying_key(), "rev0".into());
        let mut units = HashMap::new();
        units.insert("rev0".into(), 0); // zero voting power

        let id = pool.submit(make_contribution());
        let c = commit(id, &key, true, &[42u8; 32]);
        let err = pool.commit_vote(id, c, &reviewers, &units).unwrap_err();
        assert_eq!(err, ValidationError::InsufficientVotingPower);
    }

    #[test]
    fn drain_approved() {
        let mut pool = ReviewPool::new();
        let mut rng = rand::thread_rng();
        let key = SigningKey::generate(&mut rng);
        let (reviewers, units) = make_reviewer_set(&[key.clone()]);
        let q = QuorumConfig::default();

        // Submit two, approve one.
        let id1 = pool.submit(make_contribution());
        let id2 = pool.submit(Contribution {
            amount: 20,
            ..make_contribution()
        });

        let salt = [42u8; 32];
        pool.commit_vote(id1, commit(id1, &key, true, &salt), &reviewers, &units)
            .unwrap();
        pool.reveal_vote(id1, reveal(&key, true, salt), &q, &reviewers)
            .unwrap();

        let approved = pool.drain_approved();
        assert_eq!(approved.len(), 1);
        assert_eq!(approved[0].amount, 10);
        assert_eq!(pool.pending.len(), 1);
        assert_eq!(pool.pending[0].id, id2);
        assert_eq!(pool.pending[0].status, PendingStatus::Pending);
    }

    #[test]
    fn reject_stale() {
        let mut pool = ReviewPool::new();
        pool.submit(make_contribution()); // id=1
        pool.submit(make_contribution()); // id=2
        pool.submit(make_contribution()); // id=3

        pool.reject_stale(3);
        assert_eq!(pool.pending[0].status, PendingStatus::Rejected);
        assert_eq!(pool.pending[1].status, PendingStatus::Rejected);
        assert_eq!(pool.pending[2].status, PendingStatus::Pending);
    }

    #[test]
    fn pool_persistence_roundtrip() {
        let store = temp_store();
        let mut pool = ReviewPool::new();
        pool.submit(make_contribution());
        pool.submit(Contribution {
            amount: 20,
            ..make_contribution()
        });

        flush_pool(&store, &pool).unwrap();
        let loaded = load_pool(&store).unwrap();

        assert_eq!(loaded.pending.len(), 2);
        assert_eq!(loaded.pending[0].id, 1);
        assert_eq!(loaded.pending[1].id, 2);
        assert_eq!(loaded.next_id, pool.next_id);
    }

    #[test]
    fn review_status_readonly() {
        let mut pool = ReviewPool::new();
        let mut rng = rand::thread_rng();
        let key = SigningKey::generate(&mut rng);
        let (reviewers, units) = make_reviewer_set(&[key.clone()]);
        let q = QuorumConfig::default();

        let id = pool.submit(make_contribution());

        let status = pool.review_status(id, &q, &reviewers).unwrap();
        assert_eq!(status.current_approvals, 0);
        assert_eq!(status.status, PendingStatus::Pending);

        let salt = [42u8; 32];
        pool.commit_vote(id, commit(id, &key, true, &salt), &reviewers, &units)
            .unwrap();
        pool.reveal_vote(id, reveal(&key, true, salt), &q, &reviewers)
            .unwrap();

        let status = pool.review_status(id, &q, &reviewers).unwrap();
        assert_eq!(status.status, PendingStatus::Approved);
    }

    #[test]
    fn commit_on_finalized_rejected() {
        let mut pool = ReviewPool::new();
        let mut rng = rand::thread_rng();
        let key = SigningKey::generate(&mut rng);
        let (reviewers, units) = make_reviewer_set(&[key.clone()]);

        let id = pool.submit(make_contribution());
        pool.pending[0].status = PendingStatus::Rejected;

        let c = commit(id, &key, true, &[42u8; 32]);
        let err = pool.commit_vote(id, c, &reviewers, &units).unwrap_err();
        assert_eq!(
            err,
            ValidationError::ReviewAlreadyFinalized(id, PendingStatus::Rejected)
        );
    }

    #[test]
    fn self_approval_rejected() {
        let mut pool = ReviewPool::new();
        let mut rng = rand::thread_rng();
        let key = SigningKey::generate(&mut rng);

        // Reviewer is the same as contributor — should be blocked.
        let mut reviewers = HashMap::new();
        reviewers.insert(key.verifying_key(), "alice".into());
        let mut units = HashMap::new();
        units.insert("alice".into(), 100);

        let id = pool.submit(make_contribution()); // contributor = "alice"
        let c = commit(id, &key, true, &[42u8; 32]);
        let err = pool.commit_vote(id, c, &reviewers, &units).unwrap_err();
        assert_eq!(err, ValidationError::SelfApproval);
    }

    #[test]
    fn auto_approve_when_no_eligible_reviewers() {
        let mut pool = ReviewPool::new();
        let mut rng = rand::thread_rng();
        let key = SigningKey::generate(&mut rng);

        // Alice is the only reviewer and also the contributor — no eligible
        // reviewers for her own contribution.
        let mut reviewers = HashMap::new();
        reviewers.insert(key.verifying_key(), "alice".into());
        let mut units = HashMap::new();
        units.insert("alice".into(), 100);

        pool.submit(make_contribution()); // contributor = "alice"
        pool.auto_approve_if_no_reviewers(&reviewers, &units);

        assert_eq!(pool.pending[0].status, PendingStatus::Approved);
    }

    #[test]
    fn auto_approve_does_not_affect_when_eligible_reviewers_exist() {
        let mut pool = ReviewPool::new();
        let mut rng = rand::thread_rng();
        let alice = SigningKey::generate(&mut rng);
        let bob = SigningKey::generate(&mut rng);

        let mut reviewers = HashMap::new();
        reviewers.insert(alice.verifying_key(), "alice".into());
        reviewers.insert(bob.verifying_key(), "bob".into());
        let mut units = HashMap::new();
        units.insert("alice".into(), 100);
        units.insert("bob".into(), 100);

        // Alice submits contribution — Bob is eligible as a reviewer.
        pool.submit(Contribution {
            contributor: "alice".into(),
            asset_type: "code".into(),
            amount: 10,
        });
        pool.auto_approve_if_no_reviewers(&reviewers, &units);

        // Should still be Pending because Bob can review.
        assert_eq!(pool.pending[0].status, PendingStatus::Pending);
    }
}
