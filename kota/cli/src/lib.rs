//! The kota binary: run migrations, wire the app layer, serve the
//! GraphQL API. Config is env/flag-driven (lana's yaml config system
//! is deliberately not adopted at kota's current scale).
//!
//! `kota-cli dev` holds test-support helpers (e.g. deterministic
//! keystore generation for the bats e2e tests) that don't belong in
//! the server.

use anyhow::Context;
use clap::{Args, Parser, Subcommand};
use std::sync::Arc;
use tracing_subscriber::EnvFilter;

use bitcoin::Network;
use core_coordination::jobs::{FundingUtxoProvider, JobsError};
use core_coordination::psbt_session::OutPointRef;
use core_coordination::storage::InMemoryBlobStore;
use core_coordination::wallet::{FundingUtxo, Wallet};
use kota_app::{Coordination, CoordinationConfig};
use kota_server::{DynBlobStore, ServerConfig};

#[derive(Parser)]
#[command(
    name = "kota-cli",
    version,
    about = "kota — multisig custody coordination"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run migrations and serve the GraphQL API.
    Run(RunArgs),
    /// Development/test helpers.
    Dev(DevArgs),
}

#[derive(Args)]
struct RunArgs {
    /// Postgres connection string.
    #[arg(long, env = "DATABASE_URL")]
    database_url: String,
    /// Port the GraphQL server listens on.
    #[arg(long, env = "KOTA_SERVER_PORT", default_value_t = 5256)]
    port: u16,
    /// Bitcoin network this instance coordinates on.
    #[arg(long, env = "KOTA_NETWORK", default_value = "regtest")]
    network: Network,
}

#[derive(Args)]
struct DevArgs {
    #[command(subcommand)]
    command: DevCommands,
}

#[derive(Subcommand)]
enum DevCommands {
    /// Print the descriptor public key derived from a 32-byte hex
    /// seed. Deterministic per seed; the bats tests call this with
    /// fresh entropy each run (keystores feed the wallet's content
    /// address, so reused keystores would collide with previous runs'
    /// wallets).
    GenKeystore(GenKeystoreArgs),
}

#[derive(Args)]
struct GenKeystoreArgs {
    /// 32 bytes of entropy, hex-encoded.
    #[arg(long)]
    seed: String,
}

/// Chain sync (which will pair a chain backend with the wallet's
/// address index) is not built yet. PSBT-creation jobs fail against
/// this provider and retry, so proposed spends stay `Pending` rather
/// than collecting signatures against invented UTXOs.
struct UnconfiguredFunding;

impl FundingUtxoProvider for UnconfiguredFunding {
    async fn funding_utxos(
        &self,
        _wallet: &Wallet,
        _inputs: &[OutPointRef],
    ) -> Result<Vec<FundingUtxo>, JobsError> {
        Err(JobsError::Funding(
            "no funding UTXO source configured (chain sync not built yet)".to_string(),
        ))
    }
}

pub async fn run() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    match Cli::parse().command {
        Commands::Run(args) => run_server(args).await,
        Commands::Dev(dev) => match dev.command {
            DevCommands::GenKeystore(args) => gen_keystore(args),
        },
    }
}

async fn run_server(args: RunArgs) -> anyhow::Result<()> {
    let pool = sqlx::PgPool::connect(&args.database_url)
        .await
        .context("connecting to postgres")?;
    sqlx::migrate!("../../migrations")
        .run(&pool)
        .await
        .context("running migrations")?;

    let mut jobs = job::Jobs::init(
        job::JobSvcConfig::builder()
            .pool(pool.clone())
            .build()
            .map_err(|e| anyhow::anyhow!("building job config: {e}"))?,
    )
    .await
    .context("initializing job service")?;

    // Dev backend until the GCS/filesystem blob stores land: blobs
    // live in process memory, so unsigned PSBTs don't survive a
    // restart (sessions in `Collecting` would need re-proposal).
    let blobs = Arc::new(DynBlobStore::new(InMemoryBlobStore::default()));
    let app = Coordination::init(
        &pool,
        &mut jobs,
        blobs,
        Arc::new(UnconfiguredFunding),
        CoordinationConfig::new(args.network),
    );
    jobs.start_poll().await.context("starting job poller")?;

    let result = kota_server::run(ServerConfig { port: args.port }, app, shutdown_signal()).await;
    jobs.shutdown().await.context("shutting down job service")?;
    result
}

fn gen_keystore(args: GenKeystoreArgs) -> anyhow::Result<()> {
    use bitcoin::bip32::{DerivationPath, Xpriv, Xpub};
    use bitcoin::secp256k1::Secp256k1;
    use miniscript::descriptor::{DescriptorPublicKey, DescriptorXKey, Wildcard};
    use std::str::FromStr;

    let seed = decode_hex_32(&args.seed)?;
    let secp = Secp256k1::new();
    let xpriv = Xpriv::new_master(Network::Regtest, &seed)?;
    let account_path = DerivationPath::from_str("m/48'/0'/0'/2'")?;
    let account_xpriv = xpriv.derive_priv(&secp, &account_path)?;
    let keystore = DescriptorPublicKey::XPub(DescriptorXKey {
        origin: Some((xpriv.fingerprint(&secp), account_path)),
        xkey: Xpub::from_priv(&secp, &account_xpriv),
        derivation_path: DerivationPath::from_str("m/0")?,
        wildcard: Wildcard::Unhardened,
    });
    println!("{keystore}");
    Ok(())
}

fn decode_hex_32(s: &str) -> anyhow::Result<[u8; 32]> {
    let s = s.trim();
    anyhow::ensure!(s.len() == 64, "seed must be 64 hex characters");
    let mut out = [0u8; 32];
    for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
        let hi = (chunk[0] as char).to_digit(16).context("invalid hex")?;
        let lo = (chunk[1] as char).to_digit(16).context("invalid hex")?;
        out[i] = ((hi << 4) | lo) as u8;
    }
    Ok(out)
}

#[cfg(unix)]
async fn shutdown_signal() {
    use tokio::signal::unix::{SignalKind, signal};
    let mut sigterm = signal(SignalKind::terminate()).expect("install SIGTERM handler");
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {},
        _ = sigterm.recv() => {},
    }
}

#[cfg(not(unix))]
async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}
