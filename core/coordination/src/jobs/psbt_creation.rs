//! `job`-crate wiring for the PSBT-creation job unit.
//!
//! The unit of work is [`run_psbt_creation`]; below it is only the
//! scheduling adapter: config payload, initializer, and runner.

use std::sync::Arc;

use async_trait::async_trait;
use job::*;
use serde::{Deserialize, Serialize};

use bitcoin::Network;

use crate::primitives::{PsbtHash, PsbtSessionId};
use crate::psbt_session::{PsbtSessionRepo, PsbtSessionStatus, SpendSpec};
use crate::storage::BlobStore;
use crate::wallet::{WalletRepo, build_unsigned_psbt};

use super::{FundingUtxoProvider, JobsError};

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

pub const PSBT_CREATION_JOB: JobType = JobType::new("coordination.psbt-creation");

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PsbtCreationJobConfig {
    pub session_id: PsbtSessionId,
}

pub struct PsbtCreationJobInit<B, F> {
    sessions: PsbtSessionRepo,
    wallets: WalletRepo,
    blobs: Arc<B>,
    funding: Arc<F>,
    network: Network,
}

impl<B, F> PsbtCreationJobInit<B, F> {
    pub fn new(
        sessions: PsbtSessionRepo,
        wallets: WalletRepo,
        blobs: Arc<B>,
        funding: Arc<F>,
        network: Network,
    ) -> Self {
        Self {
            sessions,
            wallets,
            blobs,
            funding,
            network,
        }
    }
}

impl<B, F> JobInitializer for PsbtCreationJobInit<B, F>
where
    B: BlobStore + Send + Sync + 'static,
    F: FundingUtxoProvider + Send + Sync + 'static,
{
    type Config = PsbtCreationJobConfig;

    fn job_type(&self) -> JobType {
        PSBT_CREATION_JOB
    }

    fn init(
        &self,
        job: &Job,
        _: JobSpawner<Self::Config>,
    ) -> Result<Box<dyn JobRunner>, Box<dyn std::error::Error>> {
        Ok(Box::new(PsbtCreationJobRunner::<B, F> {
            config: job.config()?,
            sessions: self.sessions.clone(),
            wallets: self.wallets.clone(),
            blobs: self.blobs.clone(),
            funding: self.funding.clone(),
            network: self.network,
        }))
    }
}

struct PsbtCreationJobRunner<B, F> {
    config: PsbtCreationJobConfig,
    sessions: PsbtSessionRepo,
    wallets: WalletRepo,
    blobs: Arc<B>,
    funding: Arc<F>,
    network: Network,
}

#[async_trait]
impl<B, F> JobRunner for PsbtCreationJobRunner<B, F>
where
    B: BlobStore + Send + Sync + 'static,
    F: FundingUtxoProvider + Send + Sync + 'static,
{
    #[tracing::instrument(
        name = "coordination.psbt_creation_job.run",
        skip_all,
        fields(session_id = %self.config.session_id)
    )]
    async fn run(
        &self,
        _current_job: CurrentJob,
    ) -> Result<JobCompletion, Box<dyn std::error::Error>> {
        match run_psbt_creation(
            &self.sessions,
            &self.wallets,
            self.blobs.as_ref(),
            self.funding.as_ref(),
            self.network,
            self.config.session_id,
        )
        .await
        {
            Ok(hash) => {
                tracing::info!(%hash, "unsigned psbt recorded");
                Ok(JobCompletion::Complete)
            }
            // The session moved on between spawn and execution (cancelled
            // or expired while pending). It will never need a PSBT, so
            // retrying is pointless — complete as a no-op instead of
            // poisoning the retry queue.
            Err(JobsError::UnexpectedStatus { status, .. }) => {
                tracing::info!(%status, "session no longer pending, nothing to do");
                Ok(JobCompletion::Complete)
            }
            Err(e) => Err(Box::new(e)),
        }
    }
}
