//! The async job units that drive the `PsbtSession` lifecycle, plus
//! their `job`-crate scheduling adapters (one file per job type).
//!
//! Each unit of work is one idempotent function: load the aggregate, do
//! the thing, persist. The runner in the same file is a thin scheduling
//! adapter over it, registered with the `job` executor via [`register`].
//! Entity-level idempotency ([`es_entity::Idempotent`]) makes executor
//! retries safe no-ops.
//!
//! Trust boundaries enforced here:
//!
//! - the unsigned PSBT is *built* by the platform from the recorded
//!   `SpendSpec`, the wallet descriptor, and chain data — never accepted
//!   from the proposer;
//! - finalization recomputes the final transaction from the original
//!   unsigned PSBT plus the platform-built merged signature blobs
//!   (original + one signer's extracted signatures). Signer-submitted
//!   documents are never loaded back;
//! - chain observations are matched against the finalized txid by the
//!   entity (`TxidMismatch`), so a confused or malicious chain-sync
//!   source cannot attach another transaction's lifecycle to a session.

use std::sync::Arc;

use bitcoin::{BlockHash, Network, Txid};

use crate::primitives::{PsbtHash, PsbtSessionId};
use crate::psbt::PsbtValidationError;
use crate::psbt_session::{
    InvalidationReason, OutPointRef, PsbtSessionError, PsbtSessionRepo, PsbtSessionStatus,
};
use crate::storage::BlobStore;
use crate::wallet::repo::WalletFindError;
use crate::wallet::{FundingUtxo, Wallet, WalletError, WalletRepo};

mod finalization;
mod psbt_creation;

pub use finalization::{
    FINALIZATION_JOB, FinalizationJobConfig, FinalizationJobInit, run_finalization,
};
pub use psbt_creation::{
    PSBT_CREATION_JOB, PsbtCreationJobConfig, PsbtCreationJobInit, run_psbt_creation,
};

/// Spawners for the coordination job types, returned by [`register`].
/// The use-case layer spawns `psbt_creation` when a session is proposed
/// and `finalization` at every signature upload (it no-ops below
/// threshold), so the quorum never waits on a polling tick.
pub struct CoordinationJobSpawners {
    pub psbt_creation: job::JobSpawner<PsbtCreationJobConfig>,
    pub finalization: job::JobSpawner<FinalizationJobConfig>,
}

/// Register the coordination job initializers with the job service.
/// Call once at startup, before `Jobs::start_poll`.
pub fn register<B, F>(
    jobs: &mut job::Jobs,
    sessions: &PsbtSessionRepo,
    wallets: &WalletRepo,
    blobs: Arc<B>,
    funding: Arc<F>,
    network: Network,
) -> CoordinationJobSpawners
where
    B: BlobStore + Send + Sync + 'static,
    F: FundingUtxoProvider + Send + Sync + 'static,
{
    CoordinationJobSpawners {
        psbt_creation: jobs.add_initializer(PsbtCreationJobInit::new(
            sessions.clone(),
            wallets.clone(),
            blobs.clone(),
            funding,
            network,
        )),
        finalization: jobs.add_initializer(FinalizationJobInit::new(sessions.clone(), blobs)),
    }
}

#[derive(Debug, thiserror::Error)]
pub enum JobsError {
    #[error("JobsError - Session: {0}")]
    Session(#[from] PsbtSessionError),
    #[error("JobsError - SessionFind: {0}")]
    SessionFind(#[from] crate::psbt_session::repo::PsbtSessionFindError),
    #[error("JobsError - SessionModify: {0}")]
    SessionModify(#[from] crate::psbt_session::repo::PsbtSessionModifyError),
    #[error("JobsError - WalletFind: {0}")]
    WalletFind(#[from] WalletFindError),
    #[error("JobsError - Wallet: {0}")]
    Wallet(#[from] WalletError),
    #[error("JobsError - Psbt: {0}")]
    Psbt(#[from] PsbtValidationError),
    #[error("JobsError - Funding: {0}")]
    Funding(String),
    #[error(
        "JobsError - WalletNotActive: wallet {0} has no descriptor (not Active); a session \
         should never exist for an inactive wallet — this indicates an integrity violation"
    )]
    WalletNotActive(crate::primitives::WalletId),
    #[error(
        "JobsError - BlobMissing: content {0} is referenced by the event log but absent from storage"
    )]
    BlobMissing(PsbtHash),
    #[error(
        "JobsError - BlobIntegrity: bytes fetched for {0} do not hash to their content \
         address — the store returned corrupted or substituted content"
    )]
    BlobIntegrity(PsbtHash),
    #[error("JobsError - UnexpectedStatus: session {id} is {status}, expected {expected}")]
    UnexpectedStatus {
        id: PsbtSessionId,
        status: PsbtSessionStatus,
        expected: &'static str,
    },
    #[error("JobsError - ThresholdNotMet: session {0} has not collected enough signatures yet")]
    ThresholdNotMet(PsbtSessionId),
    #[error(
        "JobsError - CannotFinalize: the collected signatures did not produce a valid final \
         transaction — this should be impossible after upload-time validation and indicates \
         blob corruption or tampering"
    )]
    CannotFinalize,
}

/// External chain data the platform cannot know on its own: for each
/// outpoint a proposal spends, the full funding `TxOut` (amount +
/// scriptPubKey) and the wallet derivation index that produced it.
///
/// Implementations pair a chain backend (Esplora/electrum/bitcoind) with
/// the wallet's address index. Only the PSBT-creation job calls this.
pub trait FundingUtxoProvider {
    fn funding_utxos<'a>(
        &'a self,
        wallet: &'a Wallet,
        inputs: &'a [OutPointRef],
    ) -> impl Future<Output = Result<Vec<FundingUtxo>, JobsError>> + Send + 'a;
}

/// A chain-sync observation about a session's finalized transaction.
/// Delivered by the (future) outbox consumer — never by user commands.
pub enum ChainObservation {
    /// The finalized tx appeared in the mempool or a block.
    Broadcast { txid: Txid },
    Confirmed {
        txid: Txid,
        height: u64,
        block_hash: BlockHash,
    },
    /// Reorg, external spend of the inputs, RBF replacement, or mempool
    /// eviction. Chain states are never terminal.
    Invalidated { reason: InvalidationReason },
}

/// Chain-sync job: fold one observation into the session's lifecycle.
/// All entity transitions are idempotent (and reorg-safe via
/// `resets_on`), so redelivery during catch-up sync is a no-op and only
/// executes a persist when state actually changed.
pub async fn apply_chain_observation(
    sessions: &PsbtSessionRepo,
    session_id: PsbtSessionId,
    observation: ChainObservation,
) -> Result<(), JobsError> {
    let mut session = sessions.find_by_id(session_id).await?;

    let applied = match observation {
        ChainObservation::Broadcast { txid } => session.mark_broadcast_seen(txid)?,
        ChainObservation::Confirmed {
            txid,
            height,
            block_hash,
        } => session.confirm(txid, height, block_hash)?,
        ChainObservation::Invalidated { reason } => session.invalidate(reason)?,
    };
    if applied.did_execute() {
        sessions.update(&mut session).await?;
    }
    Ok(())
}
