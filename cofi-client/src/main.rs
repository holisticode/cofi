use clap::{Parser, Subcommand};
use cofi_contracts::validation::{VoteCommitment, VoteReveal, compute_commitment};
use cofi_contracts::{Contribution, Redemption, redemption_message};
use cofi_node::tx::{CoFiTx, encode_tx};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use std::path::Path;
use tendermint_rpc::{Client, HttpClient, Url};

#[derive(Parser)]
#[command(name = "cofi-client", version, about = "CoFi CLI client")]
struct Args {
    /// CometBFT RPC endpoint.
    #[arg(long, default_value = "http://127.0.0.1:26657")]
    node: Url,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate an Ed25519 keypair and write the seed (hex) to a file.
    Keygen {
        #[arg(long, default_value = "cofi.key")]
        key: String,
    },
    /// Submit a contribution for peer review.
    Contribution {
        #[arg(long)]
        contributor: String,
        #[arg(long)]
        asset_type: String,
        #[arg(long)]
        amount: u64,
    },
    /// Register a public key for a contributor (requires existing units).
    RegisterKey {
        #[arg(long)]
        contributor: String,
        #[arg(long)]
        key: String,
    },
    /// Commit to a review vote (phase 1 of commit-reveal).
    CommitVote {
        #[arg(long)]
        pending_id: u64,
        #[arg(long)]
        key: String,
        /// Set to false to vote against.
        #[arg(long, default_value_t = true)]
        approve: bool,
    },
    /// Reveal a review vote (phase 2 of commit-reveal).
    RevealVote {
        #[arg(long)]
        pending_id: u64,
        #[arg(long)]
        key: String,
        /// Salt hex from commit-vote output; reads vote-<id>.json if omitted.
        #[arg(long)]
        salt: Option<String>,
        /// Set to false to vote against.
        #[arg(long, default_value_t = true)]
        approve: bool,
    },
    /// Redeem contribution units (self-signed exit message).
    Redeem {
        #[arg(long)]
        contributor: String,
        #[arg(long)]
        amount: u64,
        #[arg(long)]
        key: String,
    },
    /// Query the app: `state`, `balance/<contributor>`, `pool`.
    Query {
        path: String,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let client = HttpClient::new(args.node)?;

    match args.command {
        Command::Keygen { key } => keygen(&key),
        Command::Contribution {
            contributor,
            asset_type,
            amount,
        } => {
            let tx = CoFiTx::Contribution(Contribution {
                contributor: contributor.into(),
                asset_type: asset_type.into(),
                amount,
            });
            broadcast(&client, &tx).await
        }
        Command::RegisterKey { contributor, key } => {
            let signing_key = load_key(&key)?;
            let tx = CoFiTx::RegisterKey {
                contributor_id: contributor.into(),
                public_key: signing_key.verifying_key(),
            };
            broadcast(&client, &tx).await
        }
        Command::CommitVote {
            pending_id,
            key,
            approve,
        } => {
            let signing_key = load_key(&key)?;
            let reviewer: VerifyingKey = signing_key.verifying_key();
            let salt: [u8; 32] = rand::random();
            let commitment = compute_commitment(pending_id, &reviewer, approve, &salt);
            save_vote(pending_id, approve, &salt)?;
            println!("salt: {}", hex::encode(salt));

            let tx = CoFiTx::CommitVote {
                pending_id,
                commitment: VoteCommitment {
                    reviewer,
                    commitment,
                    signature: signing_key.sign(&commitment),
                },
            };
            broadcast(&client, &tx).await
        }
        Command::RevealVote {
            pending_id,
            key,
            salt,
            approve,
        } => {
            let signing_key = load_key(&key)?;
            let (salt, approve) = match salt {
                Some(hex_salt) => {
                    let bytes = hex::decode(hex_salt)?;
                    let arr: [u8; 32] = bytes
                        .try_into()
                        .map_err(|_| "salt must be 32 bytes")?;
                    (arr, approve)
                }
                None => load_vote(pending_id)?,
            };
            let tx = CoFiTx::RevealVote {
                pending_id,
                reveal: VoteReveal {
                    reviewer: signing_key.verifying_key(),
                    approve,
                    salt,
                },
            };
            broadcast(&client, &tx).await
        }
        Command::Redeem {
            contributor,
            amount,
            key,
        } => {
            let signing_key = load_key(&key)?;
            let msg = redemption_message(&contributor, amount);
            let tx = CoFiTx::Redemption(Redemption {
                contributor: contributor.into(),
                amount,
                signature: signing_key.sign(&msg),
            });
            broadcast(&client, &tx).await
        }
        Command::Query { path } => query(&client, &path).await,
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async fn broadcast(
    client: &HttpClient,
    tx: &CoFiTx,
) -> Result<(), Box<dyn std::error::Error>> {
    let res = client.broadcast_tx_commit(encode_tx(tx)).await?;
    println!(
        "check_tx:  code={} log={}",
        res.check_tx.code.value(),
        res.check_tx.log
    );
    println!(
        "tx_result: code={} log={} height={}",
        res.tx_result.code.value(),
        res.tx_result.log,
        res.height
    );
    Ok(())
}

async fn query(client: &HttpClient, path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let res = client
        .abci_query(Some(path.to_string()), Vec::new(), None, false)
        .await?;
    if !res.code.is_ok() {
        println!("query error: code={} log={}", res.code.value(), res.log);
        return Ok(());
    }
    let text = String::from_utf8_lossy(&res.value);
    match serde_json::from_str::<serde_json::Value>(&text) {
        Ok(pretty) => println!("{}", serde_json::to_string_pretty(&pretty)?),
        Err(_) => println!("{text}"),
    }
    Ok(())
}

fn keygen(path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut rng = rand::thread_rng();
    let signing_key = SigningKey::generate(&mut rng);
    std::fs::write(path, hex::encode(signing_key.to_bytes()))?;
    println!("wrote key to {path}");
    println!("public key: {}", hex::encode(signing_key.verifying_key()));
    Ok(())
}

fn load_key(path: &str) -> Result<SigningKey, Box<dyn std::error::Error>> {
    let hex_seed = std::fs::read_to_string(path)?.trim().to_string();
    let bytes = hex::decode(hex_seed)?;
    // CometBFT writes Go-style 64-byte ed25519 keys (seed || pubkey); the
    // first 32 bytes are the seed. Our keygen writes 32 bytes.
    let seed = match bytes.len() {
        32 => bytes.try_into().unwrap(),
        64 => bytes[..32].try_into().unwrap(),
        n => return Err(format!("key seed must be 32 or 64 bytes, got {n}").into()),
    };
    Ok(SigningKey::from_bytes(&seed))
}

fn save_vote(pending_id: u64, approve: bool, salt: &[u8; 32]) -> std::io::Result<()> {
    let path = vote_file(pending_id);
    std::fs::write(
        &path,
        serde_json::json!({ "approve": approve, "salt": hex::encode(salt) }).to_string(),
    )
}

fn load_vote(pending_id: u64) -> Result<([u8; 32], bool), Box<dyn std::error::Error>> {
    let path = vote_file(pending_id);
    let data: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&path)?)?;
    let salt_hex = data["salt"].as_str().ok_or("vote file missing salt")?;
    let bytes = hex::decode(salt_hex)?;
    let arr: [u8; 32] = bytes.try_into().map_err(|_| "salt must be 32 bytes")?;
    let approve = data["approve"].as_bool().unwrap_or(true);
    Ok((arr, approve))
}

fn vote_file(pending_id: u64) -> std::path::PathBuf {
    Path::new(&format!("vote-{pending_id}.json")).to_path_buf()
}
