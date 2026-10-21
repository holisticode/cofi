use crate::governance::GovernanceConfig;
use crate::validation::QuorumConfig;
use serde::{Deserialize, Serialize};

/// Genesis configuration that seeds the system.
///
/// Applied once via `CoFiState::apply_charter`. After genesis, individual
/// fields are modified through governance proposals.
///
/// No initial reviewer set — reviewers are contributors with non-zero units.
/// The first contribution auto-approves when there are zero reviewers,
/// establishing the first reviewer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Charter {
    /// Proportional quorum for contribution review.
    pub quorum_config: QuorumConfig,
    /// Governance parameters (voting duration, thresholds).
    pub governance_config: GovernanceConfig,
}

impl Default for Charter {
    fn default() -> Self {
        Self {
            quorum_config: QuorumConfig::default(),
            governance_config: GovernanceConfig::default(),
        }
    }
}
