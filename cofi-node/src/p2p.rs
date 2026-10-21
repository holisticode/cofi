use cofi_block::Block;
use cofi_contracts::Contribution;
use libp2p::{
    StreamProtocol,
    gossipsub::{self, IdentTopic},
    identify,
    mdns,
};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Protocol constants
// ---------------------------------------------------------------------------

pub const CONTRIBUTION_TOPIC: &str = "/cofi/contributions/1.0.0";
pub const BLOCK_TOPIC: &str = "/cofi/blocks/1.0.0";

/// Maximum gossip message size: 1 MiB.
pub const MAX_MESSAGE_SIZE: usize = 1024 * 1024;

// ---------------------------------------------------------------------------
// P2P message types
// ---------------------------------------------------------------------------

/// Messages that flow over gossipsub.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GossipMessage {
    NewContribution(Contribution),
    NewBlock(Block),
}

// ---------------------------------------------------------------------------
// Composite behaviour
// ---------------------------------------------------------------------------

#[libp2p::behaviour]
pub struct CoFiBehaviour {
    pub gossipsub: gossipsub::Behaviour,
    pub mdns: mdns::tokio::Behaviour,
    pub identify: identify::Behaviour,
}

// ---------------------------------------------------------------------------
// Build the libp2p Swarm
// ---------------------------------------------------------------------------

pub fn build_swarm() -> Result<libp2p::Swarm<CoFiBehaviour>, Box<dyn std::error::Error>> {
    let id_keys = libp2p::identity::Keypair::generate_ed25519();

    let mut swarm = libp2p::SwarmBuilder::with_existing_identity(id_keys)
        .with_tokio()
        .with_tcp(
            libp2p::tcp::Config::default(),
            libp2p::noise::Config::new,
            libp2p::yamux::Config::default,
        )?
        .with_behaviour(|key| {
            // Gossipsub
            let mut gs_config = gossipsub::ConfigBuilder::default()
                .max_transmit_size(MAX_MESSAGE_SIZE)
                .build()
                .expect("valid gossipsub config");
            let gossipsub = gossipsub::Behaviour::new(
                gossipsub::MessageAuthenticity::Signed(key.clone()),
                gs_config,
            )
            .expect("valid gossipsub behaviour");

            // mDNS
            let mdns = mdns::tokio::Behaviour::new(
                mdns::Config::default(),
                key.public().to_peer_id(),
            )
            .expect("valid mdns behaviour");

            // Identify
            let identify = identify::Behaviour::new(
                identify::Config::new(
                    "/cofi/1.0.0".into(),
                    key.public(),
                ),
            );

            CoFiBehaviour {
                gossipsub,
                mdns,
                identify,
            }
        })?
        .with_swarm_config(|c| {
            c.with_idle_connection_timeout(std::time::Duration::from_secs(60))
        })
        .build();

    // Subscribe to topics.
    swarm.behaviour_mut().gossipsub.subscribe(&IdentTopic::new(CONTRIBUTION_TOPIC))?;
    swarm.behaviour_mut().gossipsub.subscribe(&IdentTopic::new(BLOCK_TOPIC))?;

    Ok(swarm)
}
