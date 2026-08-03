//! The async job units that drive the `PsbtSession` lifecycle.
//!
//! Each function is one idempotent unit of work: load the aggregate, do
//! the thing, persist. They contain no scheduling logic — an executor
//! (sqlxmq/apalis/...; decision deferred) is expected to call them with
//! retries, relying on entity-level idempotency ([`es_entity::Idempotent`])
//! to make re-runs safe no-ops.
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

use bitcoin::secp256k1;
use bitcoin::{BlockHash, Network, Psbt, Txid};
use miniscript::psbt::PsbtExt;

use crate::primitives::{PsbtHash, PsbtSessionId};
use crate::psbt::{self, PsbtValidationError};
use crate::psbt_session::{
    InvalidationReason, OutPointRef, PsbtSessionError, PsbtSessionRepo, PsbtSessionStatus,
    SpendSpec,
};
use crate::storage::BlobStore;
use crate::wallet::repo::WalletFindError;
use crate::wallet::{FundingUtxo, Wallet, WalletError, WalletRepo, build_unsigned_psbt};

mod finalization;
mod psbt_creation;

pub use finalization::{FINALIZATION_JOB, FinalizationJobConfig, FinalizationJobInit};
pub use psbt_creation::{PSBT_CREATION_JOB, PsbtCreationJobConfig, PsbtCreationJobInit};

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
        "JobsError - BlobMissing: content {0} is referenced by the event log but absent from storage"
    )]
    BlobMissing(PsbtHash),
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

/// PSBT-creation job: build the unsigned PSBT for a `Pending` session,
/// upload it to content-addressed storage, and record the hash —
/// transitioning the session to `Collecting`.
///
/// Idempotent: if the session already carries an unsigned PSBT hash, it
/// is returned without redoing any work (a retried job after a crash
/// between upload and persist just rebuilds and re-records the same
/// content address — `put` is content-addressed, so even that is a
/// no-op at the storage layer).
pub async fn run_psbt_creation(
    sessions: &PsbtSessionRepo,
    wallets: &WalletRepo,
    blobs: &impl BlobStore,
    funding: &impl FundingUtxoProvider,
    network: Network,
    session_id: PsbtSessionId,
) -> Result<PsbtHash, JobsError> {
    let mut session = sessions.find_by_id(session_id).await?;

    if let Some(hash) = session.unsigned_psbt_hash() {
        return Ok(hash);
    }
    if session.status() != PsbtSessionStatus::Pending {
        return Err(JobsError::UnexpectedStatus {
            id: session_id,
            status: session.status(),
            expected: "pending",
        });
    }

    let wallet = wallets.find_by_id(session.wallet_id).await?;
    let utxos = funding.funding_utxos(&wallet, &session.inputs).await?;
    let spend = SpendSpec {
        inputs: session.inputs.clone(),
        outputs: session.outputs.clone(),
        fee_sats: session.fee_sats,
        change_output: session.change_output.clone(),
    };
    let psbt = build_unsigned_psbt(&spend, wallet.descriptor(), &utxos, network)?;

    let hash = blobs.put(&psbt.serialize()).await;
    let _ = session.record_psbt_created(hash)?;
    sessions.update(&mut session).await?;
    Ok(hash)
}

/// Finalization job: once the threshold is met, recompute the final
/// transaction platform-side and record it (`Finalized`).
///
/// The final PSBT is assembled from the *original* unsigned PSBT plus
/// the partial signatures in the platform-built merged blobs, adding
/// signers in recording order until the transaction finalizes — so
/// `sigs_used` is the minimal recorded prefix that authorized the
/// spend, a deterministic answer to "whose signature authorized this?".
///
/// The recorded txid is computed from the exact bytes uploaded as
/// `final_tx_hash`, so the chain-sync stream (which matches on txid)
/// and the audit blob can never disagree.
///
/// Idempotent: an already-finalized session returns its recorded txid.
pub async fn run_finalization(
    sessions: &PsbtSessionRepo,
    blobs: &impl BlobStore,
    session_id: PsbtSessionId,
) -> Result<Txid, JobsError> {
    let mut session = sessions.find_by_id(session_id).await?;

    if let Some(finalization) = session.finalization() {
        return Ok(finalization.txid);
    }
    if session.status() != PsbtSessionStatus::Collecting {
        return Err(JobsError::UnexpectedStatus {
            id: session_id,
            status: session.status(),
            expected: "collecting",
        });
    }
    if !session.threshold_met() {
        return Err(JobsError::ThresholdNotMet(session_id));
    }
    let unsigned_hash = session
        .unsigned_psbt_hash()
        .expect("status Collecting implies PsbtCreated was recorded");
    let unsigned = load_psbt(blobs, unsigned_hash).await?;

    let secp = secp256k1::Secp256k1::new();
    let mut combined = unsigned;
    let mut sigs_used = Vec::new();

    for record in session.signatures() {
        let signed = load_psbt(blobs, record.signed_psbt_hash).await?;
        for (idx, input) in signed.inputs.iter().enumerate() {
            for (pk, sig) in &input.partial_sigs {
                combined.inputs[idx].partial_sigs.entry(*pk).or_insert(*sig);
            }
        }
        sigs_used.push(record.fingerprint);

        if let Ok(final_psbt) = combined.clone().finalize(&secp) {
            let tx = final_psbt
                .extract_tx()
                .map_err(|_| JobsError::CannotFinalize)?;
            let txid = tx.compute_txid();
            let final_tx_hash = blobs.put(&bitcoin::consensus::serialize(&tx)).await;
            let _ = session.finalize(txid, final_tx_hash, sigs_used)?;
            sessions.update(&mut session).await?;
            return Ok(txid);
        }
    }

    Err(JobsError::CannotFinalize)
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

/// Fetch and parse a PSBT blob. Content-addressed fetch is
/// self-verifying (the key is the content digest); a missing blob for
/// an event-log-referenced hash is a storage-integrity error, not a
/// routine miss.
async fn load_psbt(blobs: &impl BlobStore, hash: PsbtHash) -> Result<Psbt, JobsError> {
    let bytes = blobs.get(&hash).await.ok_or(JobsError::BlobMissing(hash))?;
    Ok(psbt::parse_psbt(&bytes)?)
}
