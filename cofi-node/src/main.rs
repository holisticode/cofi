use clap::Parser;
use std::path::PathBuf;
use tracing_subscriber::EnvFilter;

use cofi_node::app::CoFiApp;

/// CoFi blockchain node — ABCI application for CometBFT.
#[derive(Parser, Debug)]
#[command(name = "cofi-node", version = "0.1.0")]
struct Args {
    /// ABCI bind address (CometBFT connects here).
    #[arg(long, default_value = "127.0.0.1:26658")]
    abci_bind_addr: String,

    /// Data directory for the Sled database.
    #[arg(long, default_value = "./cofi-data")]
    data_dir: PathBuf,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("info".parse()?))
        .init();

    let args = Args::parse();

    std::fs::create_dir_all(&args.data_dir)?;
    let store_path = args.data_dir.join("sled");
    let store = cofi_contracts::store::SledStore::open(&store_path)?;

    tracing::info!("Data directory: {}", store_path.display());

    CoFiApp::run(&args.abci_bind_addr, store)?;

    Ok(())
}
