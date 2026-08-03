//! `job`-crate wiring for the finalization job unit.
//!
//! The unit of work is [`run_finalization`]; below it is only the
//! scheduling adapter: config payload, initializer, and runner.

use std::sync::Arc;

use async_trait::async_trait;
use job::*;
use serde::{Deserialize, Serialize};

use bitcoin::secp256k1;
use bitcoin::{Psbt, Txid};
use miniscript::psbt::PsbtExt;

use crate::primitives::{PsbtHash, PsbtSessionId};
use crate::psbt;
use crate::psbt_session::{PsbtSessionRepo, PsbtSessionStatus};
use crate::storage::BlobStore;

use super::JobsError;

/// Finalization job: once the threshold is met, recompute the final
/// transaction platform-side and record it (`Finalized`).
///
/// The final PSBT is assembled from the *original* unsigned PSBT plus
/// the partial signatures in the platform-built merged blobs, adding
/// signers in recording order until the transaction finalizes — so
/// `sigs_used` is the minimal recorded prefix that authorized the
/// spend, a deterministic answer to "whose signature authorized this?".
/// Every recorded blob is re-verified against the original's sighash
/// before merging (`crate::psbt::verify_merged_blob`): `finalize` only
/// checks the script is satisfied, so a corrupt blob would otherwise
/// produce an invalid tx and record it as `Finalized`.
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
    let mut combined = unsigned.clone();
    let mut sigs_used = Vec::new();

    for record in session.signatures() {
        let signed = load_psbt(blobs, record.signed_psbt_hash).await?;
        // Defense-in-depth: upload-time validation should make this
        // redundant, but `finalize` below only checks the script is
        // satisfied, not that signatures verify — a corrupt recorded
        // blob would otherwise produce an invalid tx recorded as
        // `Finalized`, bricking the session (see `verify_merged_blob`).
        psbt::verify_merged_blob(&unsigned, &signed)?;
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

/// Fetch and parse a PSBT blob. Content-addressed fetch is
/// self-verifying *by recompute-and-compare*: a missing blob for an
/// event-log-referenced hash is a storage-integrity error, and so are
/// bytes that do not hash to the address they were fetched under (a
/// corrupt or misconfigured backend is indistinguishable from
/// tampering at this layer).
async fn load_psbt(blobs: &impl BlobStore, hash: PsbtHash) -> Result<Psbt, JobsError> {
    let bytes = blobs.get(&hash).await.ok_or(JobsError::BlobMissing(hash))?;
    if PsbtHash::digest_of(&bytes) != hash {
        return Err(JobsError::BlobIntegrity(hash));
    }
    Ok(psbt::parse_psbt(&bytes)?)
}

pub const FINALIZATION_JOB: JobType = JobType::new("coordination.finalization");

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FinalizationJobConfig {
    pub session_id: PsbtSessionId,
}

pub struct FinalizationJobInit<B> {
    sessions: PsbtSessionRepo,
    blobs: Arc<B>,
}

impl<B> FinalizationJobInit<B> {
    pub fn new(sessions: PsbtSessionRepo, blobs: Arc<B>) -> Self {
        Self { sessions, blobs }
    }
}

impl<B> JobInitializer for FinalizationJobInit<B>
where
    B: BlobStore + Send + Sync + 'static,
{
    type Config = FinalizationJobConfig;

    fn job_type(&self) -> JobType {
        FINALIZATION_JOB
    }

    fn init(
        &self,
        job: &Job,
        _: JobSpawner<Self::Config>,
    ) -> Result<Box<dyn JobRunner>, Box<dyn std::error::Error>> {
        Ok(Box::new(FinalizationJobRunner::<B> {
            config: job.config()?,
            sessions: self.sessions.clone(),
            blobs: self.blobs.clone(),
        }))
    }
}

struct FinalizationJobRunner<B> {
    config: FinalizationJobConfig,
    sessions: PsbtSessionRepo,
    blobs: Arc<B>,
}

#[async_trait]
impl<B> JobRunner for FinalizationJobRunner<B>
where
    B: BlobStore + Send + Sync + 'static,
{
    #[tracing::instrument(
        name = "coordination.finalization_job.run",
        skip_all,
        fields(session_id = %self.config.session_id)
    )]
    async fn run(
        &self,
        _current_job: CurrentJob,
    ) -> Result<JobCompletion, Box<dyn std::error::Error>> {
        match run_finalization(&self.sessions, self.blobs.as_ref(), self.config.session_id).await {
            Ok(txid) => {
                tracing::info!(%txid, "session finalized");
                Ok(JobCompletion::Complete)
            }
            // Spawned eagerly (e.g. at every signature upload): below
            // threshold is not an error, just nothing to do yet — a later
            // upload will spawn this job again.
            Err(JobsError::ThresholdNotMet(_)) => {
                tracing::info!("threshold not met, nothing to finalize");
                Ok(JobCompletion::Complete)
            }
            // The session moved on between spawn and execution (cancelled,
            // expired, broadcast by a previous run, ...). It will never
            // become finalizable again, so retrying is pointless — complete
            // as a no-op instead of poisoning the retry queue.
            Err(JobsError::UnexpectedStatus { status, .. }) => {
                tracing::info!(%status, "session no longer finalizable, nothing to do");
                Ok(JobCompletion::Complete)
            }
            Err(e) => Err(Box::new(e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::InMemoryBlobStore;
    use bitcoin::hashes::Hash;
    use bitcoin::{
        Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness, absolute,
        transaction::Version,
    };

    fn some_psbt_bytes() -> Vec<u8> {
        let tx = Transaction {
            version: Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_byte_array([7; 32]),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: ScriptBuf::new(),
            }],
        };
        Psbt::from_unsigned_tx(tx).unwrap().serialize()
    }

    /// A store that returns attacker-controlled bytes for any key.
    struct LyingStore(Vec<u8>);

    impl BlobStore for LyingStore {
        async fn put(&self, bytes: &[u8]) -> PsbtHash {
            PsbtHash::digest_of(bytes)
        }
        async fn get(&self, _: &PsbtHash) -> Option<Vec<u8>> {
            Some(self.0.clone())
        }
        async fn delete(&self, _: &PsbtHash) -> bool {
            false
        }
    }

    #[tokio::test]
    async fn fetch_round_trips_honest_store() {
        let store = InMemoryBlobStore::default();
        let hash = store.put(&some_psbt_bytes()).await;
        assert!(load_psbt(&store, hash).await.is_ok());
    }

    #[tokio::test]
    async fn fetch_rejects_bytes_that_do_not_hash_to_the_key() {
        let real = some_psbt_bytes();
        let hash = PsbtHash::digest_of(&real);
        let substituted = some_psbt_bytes()[..40].to_vec();
        assert!(matches!(
            load_psbt(&LyingStore(substituted), hash).await,
            Err(JobsError::BlobIntegrity(h)) if h == hash
        ));
    }

    #[tokio::test]
    async fn fetch_rejects_missing_blob() {
        let store = InMemoryBlobStore::default();
        let hash = PsbtHash::digest_of(b"never-stored");
        assert!(matches!(
            load_psbt(&store, hash).await,
            Err(JobsError::BlobMissing(h)) if h == hash
        ));
    }
}
