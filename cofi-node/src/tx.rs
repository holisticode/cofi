use cofi_contracts::{Contribution, ContributorId, Redemption};
use cofi_contracts::validation::{VoteCommitment, VoteReveal};
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};

/// On-chain transactions that CometBFT gossips, orders, and delivers.
///
/// Every node processes the same txs in the same order, so the ReviewPool
/// assigns deterministic sequential IDs.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum CoFiTx {
    /// Submit a contribution for peer review. Enters the ReviewPool as Pending.
    #[serde(rename = "contribution")]
    Contribution(Contribution),

    /// Redeem contribution units for asset units. Applied immediately — no
    /// review needed since redemptions are self-signed.
    #[serde(rename = "redemption")]
    Redemption(Redemption),

    /// Register an Ed25519 public key. Requires existing contribution_units.
    #[serde(rename = "register_key")]
    RegisterKey {
        contributor_id: ContributorId,
        public_key: VerifyingKey,
    },

    /// Phase 1 of contribution review: commit to a vote without revealing it.
    #[serde(rename = "commit_vote")]
    CommitVote {
        pending_id: u64,
        commitment: VoteCommitment,
    },

    /// Phase 2 of contribution review: reveal the vote and salt.
    #[serde(rename = "reveal_vote")]
    RevealVote {
        pending_id: u64,
        reveal: VoteReveal,
    },
}

/// Encode a transaction for submission to CometBFT's mempool (`broadcast_tx_*`).
///
/// The node itself only decodes, but this function documents the on-wire format
/// for anyone building a client or SDK against this node.
pub fn encode_tx(tx: &CoFiTx) -> Vec<u8> {
    serde_json::to_vec(tx).expect("CoFiTx serialization is infallible")
}

/// Decode a transaction submitted via CometBFT's mempool. Used by the node
/// in `check_tx` and `finalize_block`.
pub fn decode_tx(bytes: &[u8]) -> Result<CoFiTx, serde_json::Error> {
    serde_json::from_slice(bytes)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use cofi_contracts::{AssetId, ContributorId, Contribution, Redemption};
    use ed25519_dalek::Signer;

    #[test]
    fn roundtrip_contribution() {
        let tx = CoFiTx::Contribution(Contribution {
            contributor: ContributorId::from("alice"),
            asset_type: AssetId::from("code"),
            amount: 10,
        });
        let decoded = decode_tx(&encode_tx(&tx)).unwrap();
        assert_roundtrip(&tx, &decoded);
    }

    #[test]
    fn roundtrip_redemption() {
        let mut rng = rand::thread_rng();
        let key = ed25519_dalek::SigningKey::generate(&mut rng);
        let msg = cofi_contracts::redemption_message("alice", 30);
        let tx = CoFiTx::Redemption(Redemption {
            contributor: ContributorId::from("alice"),
            amount: 30,
            signature: key.sign(&msg),
        });
        let decoded = decode_tx(&encode_tx(&tx)).unwrap();
        assert_roundtrip(&tx, &decoded);
    }

    #[test]
    fn roundtrip_register_key() {
        let mut rng = rand::thread_rng();
        let key = ed25519_dalek::SigningKey::generate(&mut rng);
        let tx = CoFiTx::RegisterKey {
            contributor_id: ContributorId::from("alice"),
            public_key: key.verifying_key(),
        };
        let decoded = decode_tx(&encode_tx(&tx)).unwrap();
        assert_roundtrip(&tx, &decoded);
    }

    #[test]
    fn roundtrip_commit_vote() {
        let mut rng = rand::thread_rng();
        let key = ed25519_dalek::SigningKey::generate(&mut rng);
        let vk = key.verifying_key();
        let salt = [42u8; 32];
        let commitment = cofi_contracts::validation::compute_commitment(1, &vk, true, &salt);
        let tx = CoFiTx::CommitVote {
            pending_id: 1,
            commitment: VoteCommitment {
                reviewer: vk,
                commitment,
                signature: key.sign(&commitment),
            },
        };
        let decoded = decode_tx(&encode_tx(&tx)).unwrap();
        assert_roundtrip(&tx, &decoded);
    }

    #[test]
    fn roundtrip_reveal_vote() {
        let mut rng = rand::thread_rng();
        let key = ed25519_dalek::SigningKey::generate(&mut rng);
        let tx = CoFiTx::RevealVote {
            pending_id: 2,
            reveal: VoteReveal {
                reviewer: key.verifying_key(),
                approve: true,
                salt: [7u8; 32],
            },
        };
        let decoded = decode_tx(&encode_tx(&tx)).unwrap();
        assert_roundtrip(&tx, &decoded);
    }

    #[test]
    fn decode_invalid_json_returns_error() {
        assert!(decode_tx(b"not json").is_err());
    }

    #[test]
    fn decode_valid_json_wrong_shape_returns_error() {
        assert!(decode_tx(b"{\"type\": \"unknown\"}").is_err());
    }

    fn assert_roundtrip(original: &CoFiTx, decoded: &CoFiTx) {
        // CoFiTx doesn't derive PartialEq, so compare via serialization.
        let re_encoded = encode_tx(decoded);
        let original_encoded = encode_tx(original);
        assert_eq!(re_encoded, original_encoded);
    }
}
