//! `job`-crate wiring for the PSBT-creation job unit.
//!
//! The unit of work lives in [`super::run_psbt_creation`]; this file is
//! only the scheduling adapter: config payload, initializer, and runner.

use std::sync::Arc;

use async_trait::async_trait;
use job::*;
use serde::{Deserialize, Serialize};

use bitcoin::Network;

use crate::primitives::PsbtSessionId;
use crate::psbt_session::PsbtSessionRepo;
use crate::storage::BlobStore;
use crate::wallet::WalletRepo;

use super::{FundingUtxoProvider, run_psbt_creation};

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
        run_psbt_creation(
            &self.sessions,
            &self.wallets,
            self.blobs.as_ref(),
            self.funding.as_ref(),
            self.network,
            self.config.session_id,
        )
        .await?;
        Ok(JobCompletion::Complete)
    }
}
