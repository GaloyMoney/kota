//! `job`-crate wiring for the finalization job unit.
//!
//! The unit of work lives in [`super::run_finalization`]; this file is
//! only the scheduling adapter: config payload, initializer, and runner.

use std::sync::Arc;

use async_trait::async_trait;
use job::*;
use serde::{Deserialize, Serialize};

use crate::primitives::PsbtSessionId;
use crate::psbt_session::PsbtSessionRepo;
use crate::storage::BlobStore;

use super::{JobsError, run_finalization};

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
            Err(e) => Err(Box::new(e)),
        }
    }
}
